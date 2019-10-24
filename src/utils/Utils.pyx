

cdef unsigned int convert_bytes_to_uint(bytearray value):

    """
    Converts value to an unsigned int.
    
    :param value: Bytearray of max length 4 that should be converted to an unsigned int.
    :return: Converted value.
    """
    return (int.from_bytes(value, byteorder='big', signed=False))

cdef unsigned long convert_bytes_to_ulong(bytearray value):

    """
    Converts value greater 4 and smaller 8 bytes to an unsigned long.
    
    :param value: Bytearray with length between 5 ad 8 inclusively.
    :return: Converted value.
    """

    # Assumption: long has 64 bits
    # 11:22:33:44:55:66
    # msb = 11:22
    # lsb = 33:44:55:66

    # 4 msb bytes
    cdef unsigned int msb_bytes
    # 4 lsb bytes
    cdef unsigned int lsb_bytes

    cdef unsigned long result

    if len(value) > 4:
        lsb_bytes = convert_bytes_to_uint(value[len(value) - 4 : len(value)])
        msb_bytes = convert_bytes_to_uint(value[ 0 : len(value) - 4])

        # 4294967296 = 2^32
        result = msb_bytes * 4294967296 + lsb_bytes

        return result
    else:
        return <unsigned long>convert_bytes_to_uint(value)