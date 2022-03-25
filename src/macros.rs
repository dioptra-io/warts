macro_rules! push_flag {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        if $d.is_some() {
            $a.push($c);
        }
        $b += $d.warts_size();
    };
}
