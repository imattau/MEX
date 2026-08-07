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

        uint256[2] memory negAcc = _negate(acc);

        uint256[2] memory negAlpha = _negate(vk.alpha);
        uint256[2][2] memory negDelta = [_negate(vk.delta[0]), vk.delta[1]];

        uint256[4] memory pairingInput = [
            a[0], a[1],
            b[0][0], b[0][1]
        ];

        uint256[2] memory pairingInputGamma = [
            negAcc[0], negAcc[1]
        ];

        uint256[2] memory pairingInputDelta = [
            c[0], c[1]
        ];

        uint256[2] memory pairingInputAlpha = [
            negAlpha[0], negAlpha[1]
        ];

        uint256[24] memory inputs_for_pairing;
        inputs_for_pairing[0] = pairingInput[0];
        inputs_for_pairing[1] = pairingInput[1];
        inputs_for_pairing[2] = b[1][0];
        inputs_for_pairing[3] = b[1][1];
        inputs_for_pairing[4] = pairingInputGamma[0];
        inputs_for_pairing[5] = pairingInputGamma[1];
        inputs_for_pairing[6] = vk.gamma[1][0];
        inputs_for_pairing[7] = vk.gamma[1][1];
        inputs_for_pairing[8] = pairingInputDelta[0];
        inputs_for_pairing[9] = pairingInputDelta[1];
        inputs_for_pairing[10] = negDelta[1][0];
        inputs_for_pairing[11] = negDelta[1][1];
        inputs_for_pairing[12] = pairingInputAlpha[0];
        inputs_for_pairing[13] = pairingInputAlpha[1];
        inputs_for_pairing[14] = vk.beta[0][0];
        inputs_for_pairing[15] = vk.beta[0][1];
        inputs_for_pairing[16] = negDelta[0][0];
        inputs_for_pairing[17] = negDelta[0][1];
        inputs_for_pairing[18] = vk.beta[1][0];
        inputs_for_pairing[19] = vk.beta[1][1];
        inputs_for_pairing[20] = vk.gamma[0][0];
        inputs_for_pairing[21] = vk.gamma[0][1];
        inputs_for_pairing[22] = vk.alpha[0];
        inputs_for_pairing[23] = vk.alpha[1];

        (bool success, bytes memory result) = address(0x08).staticcall(
            abi.encodePacked(inputs_for_pairing)
        );
        require(success, "Pairing check failed");

        bool valid = result.length == 32 && result[31] == 0x01;
        emit ProofVerified(bytes32(input[0]), valid);
        return valid;
    }

    function _negate(uint256[2] memory p)
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
