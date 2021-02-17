function get_digest(rec)
    info("Digest:%s", tostring(record.digest(rec)))
    return record.digest(rec)
end

function get_key(rec)
    info("Key:%s", tostring(record.key(rec)))
    return record.key(rec)
end

function get_ttl(rec)
    info("ttl:%s", tostring(record.ttl(rec)))
    return record.ttl(rec)
end

function get_gen(rec)
    info("gen:%s", tostring(record.gen(rec)))
    return record.gen(rec)
end

function get_setname(rec)
    info("setname:%s", tostring(record.setname(rec)))
    return record.setname(rec)
end

function get_numbins(rec)
    info("numbins:%s", tostring(record.numbins(rec)))
    return record.numbins(rec)
end

function get_bin_names(rec)
    info("bin_names:%s", tostring(record.bin_names(rec)))
    return record.bin_names(rec)
end

function set_ttl(rec, ttl)
    record.set_ttl(rec, ttl)
    aerospike:update(rec)
    return record.set_ttl(rec)
end

function rem_key(rec)
    record.drop_key(rec)
    aerospike:update(rec)
    return record.key(rec)
end