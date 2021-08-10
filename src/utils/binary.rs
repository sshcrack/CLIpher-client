pub fn constant_time_compare(a: String, b: String) -> bool {
    let a_len = a.len();
    let b_len = b.len();

    if a_len != b_len {
        return false;
    }

    let mut sentinel = 0;
    let mut a_chars = a.chars();
    let mut b_chars = b.chars();
    for _i in 0..a_len {
        let curr_a_opt = a_chars.next();
        let curr_b_opt = b_chars.next();

        if curr_a_opt.is_none() || curr_b_opt.is_none() {
            return false;
        }

        let curr_a = curr_a_opt.unwrap() as u32;
        let curr_b = curr_b_opt.unwrap() as u32;

        sentinel |= curr_a ^ curr_b;
    }

    println!("Sentinel {}", sentinel);
    return sentinel == 0;
}