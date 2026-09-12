"""Small fixtures shared by parser tests."""


def memory_reader(data, base=0x1000, code=True, **kwargs):
    """Make a parser Reader over one exactly bounded byte string."""
    # Lazy so unittest discovery itself does not import the plugin.  The
    # environment smoke test then proves Binary Ninja found the symlink.
    from delphinja.rtti.parser import Reader

    data = bytes(data)
    end = base + len(data)

    def read(addr, length):
        if addr < base or length < 0 or addr + length > end:
            return b""
        offset = addr - base
        return data[offset:offset + length]

    def mapped(addr):
        return base <= addr < end

    is_code = mapped if code else lambda _addr: False
    return Reader(read, mapped, is_code=is_code, **kwargs)
