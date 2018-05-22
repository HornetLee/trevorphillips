
BLOCK_SIZE = 4096

DIGEST_SHA256 = 32

RE_VERITY_TABLE = ".*loading verity table:.*(0|1) (.*) (.*) (.*) (.*) (.*) (.*) (sha256|md5|sha1) (.{64}) (.{64}) .*"  
RE_VERITY_TABLE_IMAGE = "(0|1) (.*) (.*) (.*) (.*) (.*) (.*) (sha256|md5|sha1) (.{64}) (.{64})"  
RE_VERITY_PART_NAME = "/dev/block/.*/by-name/(.*)"
RE_VERITY_CORRUPT_BLOCK_N = ".*\[([0-7]): .*device-mapper: verity:.*(data|meta) block (.*) is corrupted"
RE_VERITY_CORRUPT_SALT =".*\[([0-7]): .*device-mapper: verity: dm-verity salt: (.*)"
RE_VERITY_CORRUPT_VA   =".*\[([0-7]): .*_to_dump (.*)"
RE_VERITY_CORRUPT_DUMP =".*\[([0-7]): .*(0x0[0-9a-fA-F][0-9a-fA-F]0) :(( [0-9a-f]{2}){16})"

RE_VERITY_FIPS_FAILURE =".*FIPS : POST.*(failed|Failed|FIPS Error)"
RE_QB_BIN = "(ALL|AP|CSC)_.*(QB[0-9]{8,10}).*"
RE_QB_ID  = ".*https?://.*qb.*sec.samsung.net/.*([0-9]{8})"
RE_QB_ID2 = ".*QB([0-9]{8})"
