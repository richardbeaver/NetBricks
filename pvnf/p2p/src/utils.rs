use std::io::Error;
use std::process::Command;

/// Run BitTorrent jobs via deluge console
pub fn bt_run_torrents(workload: Vec<i64>) -> Result<(), Error> {
    let mut argv = Vec::new();
    argv.push("sudo".to_string());
    argv.push("-u".to_string());
    argv.push("jethros".to_string());
    argv.push("/home/jethros/dev/pvn/utils/p2p_expr/p2p_run_nb.sh".to_string());
    argv.push(workload.len().to_string());
    println!("workload {:?}", workload);
    for img in workload {
        println!("img {:?}", img);
        argv.push(img.to_string());
    }
    println!("argv {:?}", argv);

    let _ = Command::new(&argv[0])
        .args(&argv[1..])
        .spawn()
        .expect("failed to execute process");

    Ok(())
}
