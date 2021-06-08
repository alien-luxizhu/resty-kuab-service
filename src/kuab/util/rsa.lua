require("resty.string")
local ffi = require("ffi")
local Rsa = ffi.C
local ffi_gc = ffi.gc

local _M = { _VERSION = '0.0.1' }
local _Mt = { __index = _M }

ffi.cdef [[
typedef struct rsa_st RSA;
typedef struct bio_st BIO;
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
 
int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,int padding);
int RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,int padding);
int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,int padding);
int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,int padding);
 
BIO *BIO_new_mem_buf(void *buf, int len);
void BIO_free_all(BIO *a);
RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
int RSA_size(const RSA *r);
void RSA_free(RSA *rsa);
]]

local RSA_PKCS1_PADDING = 1

local function init_public_key(pem_key)
    local bio = Rsa.BIO_new_mem_buf(ffi.cast("unsigned char *", pem_key), -1)
    local rsa = Rsa.PEM_read_bio_RSA_PUBKEY(bio, nil, nil, nil);
    if rsa == nil then
        return nil, "parse public key fail"
    end
    ffi_gc(bio, Rsa.BIO_free_all)
    return rsa, nil
end
local function init_private_key(pem_key)
    local bio = Rsa.BIO_new_mem_buf(ffi.cast("unsigned char *", pem_key), -1)
    local rsa = Rsa.PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil);
    if rsa == nil then
        return nil, "parse public key fail"
    end
    ffi_gc(bio, Rsa.BIO_free_all)
    return rsa, nil
end

function _M.public_decrypt(key, data)
    local pkey = self.public_key
    local size = tonumber(Rsa.RSA_size(pkey))
    local decrypted = ffi.new("unsigned char[?]", size)
    data = ffi.cast("const unsigned char *", data)
    local len = Rsa.RSA_public_decrypt(size, data, decrypted, pkey, RSA_PKCS1_PADDING)
    return ffi.string(decrypted, len), len
end

function _M.public_encrypt(key, data)
    local pkey = self.public_key
    local size = tonumber(Rsa.RSA_size(pkey))
    local encrypted = ffi.new("unsigned char[?]", size)
    local len = Rsa.RSA_public_encrypt(#data, data, encrypted, pkey, RSA_PKCS1_PADDING)
    return ffi.string(encrypted, len), len
end

function _M.private_encrypt(self, data)
    local pkey = self.private_key
    local size = tonumber(Rsa.RSA_size(pkey))
    local encrypted = ffi.new("unsigned char[?]", size)
    local len = Rsa.RSA_private_encrypt(#data, data, encrypted, pkey, RSA_PKCS1_PADDING)
    return ffi.string(encrypted, len), len
end

function _M.private_decrypt(self, data)
    local pkey = self.private_key
    local size = tonumber(Rsa.RSA_size(pkey))
    local plain = ffi.new("unsigned char[?]", size)
    local len = Rsa.RSA_private_decrypt(#data, data, plain, pkey, RSA_PKCS1_PADDING)
    return ffi.string(plain, len), len
end

function _M.get_public_key_from_line(key)
    local key_len = #key
    local loop = 0
    for i = 64, key_len, 64 do
        key = string.insert(key, '\n', i + loop)
        loop = loop + 1
    end
    return "-----BEGIN PUBLIC KEY-----\n" .. key .. "\n-----END PUBLIC KEY-----\n"
end

function _M.get_private_key_from_line(key)
    local key_len = #key
    local loop = 0
    for i = 64, key_len, 64 do
        key = string.insert(key, '\n', i + loop)
        loop = loop + 1
    end
    return "-----BEGIN RSA PRIVATE KEY-----\n" .. key .. "\n-----END RSA PRIVATE KEY-----\n"
end

function _M.new(opt)
    local private_key, public_key, err
    if opt.private_key then
        private_key, err = init_private_key(opt.private_key)
        if not private_key then
            return nil, err
        end
        ffi_gc(private_key, Rsa.RSA_free)
    end

    if opt.public_key then
        public_key, err = init_public_key(opt.public_key)
        if not public_key then
            return nil, err
        end
        ffi_gc(public_key, Rsa.RSA_free)
    end

    return setmetatable({
        public_key = public_key,
        private_key = private_key
    }, _Mt)
end

return _M