fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("ui/assets/SecuraFolder.ico");
        res.compile().expect("Failed to compile resources");
    }

    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/window.slint", config).unwrap();
}
