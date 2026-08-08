// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchVerifier {
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[2][] ic;
    }

    VerifyingKey private vk;

    event ProofVerified(bytes32 indexed batchRoot, bool valid);

    constructor(
        uint256[2] memory alpha,
        uint256[2][2] memory beta,
        uint256[2][2] memory gamma,
        uint256[2][2] memory delta,
        uint256[2][] memory ic
    ) {
        vk.alpha = alpha;
        vk.beta = beta;
        vk.gamma = gamma;
        vk.delta = delta;
        for (uint256 i = 0; i < ic.length; i++) {
            vk.ic.push(ic[i]);
        }
    }

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) public returns (bool) {
        require(input.length + 1 == vk.ic.length, "Input length mismatch");

        uint256 snark_scalar_field =
            21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256[] memory inputs = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field, "Input exceeds scalar field");
            inputs[i] = input[i];
        }

        return _verifyGroth16(a, b, c, inputs);
    }

    // Verifies e(A,B) == e(alpha,beta) * e(vk_x,gamma) * e(C,delta), the
    // Groth16 verification equation, via the single-multi-pairing form
    // e(A,B) * e(-alpha,beta) * e(-vk_x,gamma) * e(-C,delta) == 1
    // using the alt_bn128 pairing precompile at address 0x08.
    //
    // Each of the 4 terms above is one (G1, G2) pair; the precompile expects
    // them concatenated as 4 * 6 = 24 words: G1.x, G1.y, then G2 as
    // (x.c1, x.c0, y.c1, y.c0) per EIP-197 -- imaginary component first.
    // G2 points here are stored as [X, Y] with each of X/Y itself [c0, c1].
    function _verifyGroth16(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory input
    ) private returns (bool) {
        uint256[2] memory acc = vk.ic[0];
        for (uint256 i = 0; i < input.length; i++) {
            uint256[2] memory scaled = _scalarMul(vk.ic[i + 1], input[i]);
            acc = _ecAdd(acc, scaled);
        }

        uint256[2] memory negAcc = _negateG1(acc);
        uint256[2] memory negAlpha = _negateG1(vk.alpha);
        uint256[2] memory negC = _negateG1(c);

        uint256[24] memory inputs_for_pairing;

        // e(A, B)
        inputs_for_pairing[0] = a[0];
        inputs_for_pairing[1] = a[1];
        inputs_for_pairing[2] = b[0][1];
        inputs_for_pairing[3] = b[0][0];
        inputs_for_pairing[4] = b[1][1];
        inputs_for_pairing[5] = b[1][0];

        // e(-alpha, beta)
        inputs_for_pairing[6] = negAlpha[0];
        inputs_for_pairing[7] = negAlpha[1];
        inputs_for_pairing[8] = vk.beta[0][1];
        inputs_for_pairing[9] = vk.beta[0][0];
        inputs_for_pairing[10] = vk.beta[1][1];
        inputs_for_pairing[11] = vk.beta[1][0];

        // e(-vk_x, gamma)
        inputs_for_pairing[12] = negAcc[0];
        inputs_for_pairing[13] = negAcc[1];
        inputs_for_pairing[14] = vk.gamma[0][1];
        inputs_for_pairing[15] = vk.gamma[0][0];
        inputs_for_pairing[16] = vk.gamma[1][1];
        inputs_for_pairing[17] = vk.gamma[1][0];

        // e(-C, delta)
        inputs_for_pairing[18] = negC[0];
        inputs_for_pairing[19] = negC[1];
        inputs_for_pairing[20] = vk.delta[0][1];
        inputs_for_pairing[21] = vk.delta[0][0];
        inputs_for_pairing[22] = vk.delta[1][1];
        inputs_for_pairing[23] = vk.delta[1][0];

        (bool success, bytes memory result) = address(0x08).staticcall(
            abi.encodePacked(inputs_for_pairing)
        );
        require(success, "Pairing check failed");

        bool valid = result.length == 32 && result[31] == 0x01;
        emit ProofVerified(bytes32(input[0]), valid);
        return valid;
    }

    // Negates a G1 point (x, y) -> (x, -y). Only valid for G1 -- a G2
    // point's Y coordinate is a full Fq2 element ([c0, c1]), not a single
    // uint256, so it cannot be negated with this function. (A previous
    // version of this contract incorrectly did exactly that, negating one
    // word of a G2 point's X coordinate instead of its Y coordinate.)
    function _negateG1(uint256[2] memory p)
        private
        pure
        returns (uint256[2] memory)
    {
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p[0] == 0 && p[1] == 0) {
            return [uint256(0), uint256(0)];
        }
        return [p[0], q - (p[1] % q)];
    }

    function _ecAdd(
        uint256[2] memory p1,
        uint256[2] memory p2
    ) private view returns (uint256[2] memory) {
        uint256[4] memory input;
        input[0] = p1[0];
        input[1] = p1[1];
        input[2] = p2[0];
        input[3] = p2[1];

        (bool success, bytes memory result) = address(0x06).staticcall(
            abi.encodePacked(input)
        );
        require(success, "EC Add failed");
        (uint256 x, uint256 y) = abi.decode(result, (uint256, uint256));
        return [x, y];
    }

    function _scalarMul(
        uint256[2] memory p,
        uint256 s
    ) private view returns (uint256[2] memory) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;

        (bool success, bytes memory result) = address(0x07).staticcall(
            abi.encodePacked(input)
        );
        require(success, "Scalar mul failed");
        (uint256 x, uint256 y) = abi.decode(result, (uint256, uint256));
        return [x, y];
    }
}
