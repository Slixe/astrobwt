mod astrobwt;

fn main() {
    let input = b"$BANANA";
    println!("input: {:?}", input);
    println!("Max Length: {}", astrobwt::MAX_LENGTH);
    astrobwt::compute(input, astrobwt::MAX_LENGTH);
    //println!("{:?}", hash);
}
