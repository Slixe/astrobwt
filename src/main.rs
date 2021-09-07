mod astrobwt;
mod salsa20;

use std::time::Instant;
use std::thread;

fn main() {
    let iterations = 100;
    println!("{:20} {:20} {:20} {:20} {:20}", "Threads", "Total Time", "Total Iterations", "Time/PoW (ms)", "Hash Rate/Sec");
    for bench in 1..=8 {
        let start = Instant::now();
        let mut handles = vec![];
        for _ in 0..bench {
            let handle = thread::spawn(move || {
                for _ in 0..iterations {
                    let random_bytes: Vec<u8> = (0..255).map(|_| { rand::random::<u8>() }).collect();
                    astrobwt::compute(&random_bytes, astrobwt::MAX_LENGTH);
                }
            });
            handles.push(handle);
        }

        for handle in handles { //wait on all threads
            handle.join().unwrap();
        }
        let duration = start.elapsed().as_millis();
        println!("{:20} {:20} {:20} {:20} {:20}", bench, duration, bench*iterations, duration/(bench*iterations), 1000f32 / (duration as f32 / (bench*iterations) as f32));
    }
}