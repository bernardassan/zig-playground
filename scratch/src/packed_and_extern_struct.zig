test {
    const T = packed struct { a: u8, b: u8, c: u8 };
    @compileLog(@bitSizeOf(T)); // bitsize of 24 bits
    @compileLog(@alignOf(T)); // alginment of 4 bytes so it can be loading in a single sweep
    @compileLog(@sizeOf(T)); //  size of 4 bytes because of alginment based on backing integer
}

test {
    const T = extern struct { a: u8, b: u8, c: u8 };
    @compileLog(@bitSizeOf(T)); // 24
    @compileLog(@alignOf(T)); // alginment of 1 byte ,.ie bit aligned
    @compileLog(@sizeOf(T)); // size of 3 bytes because of bit alignment
}
