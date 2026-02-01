fn main() {
    println!("OS: {}", std::env::consts::OS);
    println!("ARCH: {}", std::env::consts::ARCH);
    println!("cwd: {:?}", std::env::current_dir().unwrap());
    println!("envs:");
    for (key, value) in std::env::vars_os() {
        println!("  {:?} = {:?}", key, value);
    }
    println!("current_exe: {:?}", std::env::current_exe().unwrap());
    println!("args:");
    for arg in std::env::args_os() {
        println!("  {:?}", arg);
    }
    std::process::exit(2)
}
