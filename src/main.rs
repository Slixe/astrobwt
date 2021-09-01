mod astrobwt;
mod salsa20;

fn main() {
    let input = b"$BANANA";
    let hash = astrobwt::compute(input, astrobwt::MAX_LENGTH);
    println!("{:?}", hash);
}
