use wasmtime::*;

pub struct WasmSandbox {
    pub engine: Engine,
}

impl WasmSandbox {
    pub fn new() -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true); // Enable CPU cycle/fuel metering

        let engine = Engine::new(&config).map_err(|e| e.to_string())?;
        Ok(Self { engine })
    }

    pub fn execute_strategy(&self, wasm_wat: &str, fuel_limit: u64) -> Result<i32, String> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(fuel_limit).map_err(|e| e.to_string())?;

        // Wasmtime compiles WAT strings automatically
        let module = Module::new(&self.engine, wasm_wat).map_err(|e| e.to_string())?;
        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| e.to_string())?;

        // Call the strategy's "on_tick" entrypoint
        let on_tick = instance
            .get_typed_func::<(), i32>(&mut store, "on_tick")
            .map_err(|e| e.to_string())?;

        let result = on_tick.call(&mut store, ()).map_err(|e| e.to_string())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_execution_success() {
        let sandbox = WasmSandbox::new().unwrap();
        // A simple WAT strategy returning 42
        let wat = r#"
            (module
                (func (export "on_tick") (result i32)
                    i32.const 42
                )
            )
        "#;

        let result = sandbox.execute_strategy(wat, 1000).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_sandbox_out_of_fuel() {
        let sandbox = WasmSandbox::new().unwrap();
        // A strategy containing a loop that will consume lots of fuel
        let wat = r#"
            (module
                (func (export "on_tick") (result i32)
                    (local $i i32)
                    (local.set $i (i32.const 0))
                    (loop $my_loop
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $my_loop)
                    )
                    i32.const 0
                )
            )
        "#;

        let result = sandbox.execute_strategy(wat, 50);
        assert!(result.is_err());
    }
}
