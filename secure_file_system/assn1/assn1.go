package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib

	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	//userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type FileStruct struct {
	//Block_num int
	Location string // string pointer/???
	AES_key  string //NEED to specify length of array????
	HMAC_key string
	//Size     int
}

type FileInode struct {
	Filename string
	Location string
	//Location string
	AES_key         string
	HMAC_key        string
	Num_blocks_addr string
}

// The structure definition for a user record
type User struct {
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	//Username    string // TODO We are currently not checking if username and password after getting user struct are the same or not
	//Password    string
	Private_key *userlib.PrivateKey
	MasterInode string
	//Numfiles    int
	Numfiles_addr string
	AES_key       string
	HMAC_key      string // AES and hmac key for encrypting Master Inode
	//Files       []FileInode // TODO Storing Pointer of any use??????????
	// Method 2: Update User struct after every store file operation? store in string etc?
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

func intToByte(x int) []byte {
	a, _ := json.Marshal(x)
	return a
}
func getNumFiles(userdata *User) (f int) {
	userlib.DebugMsg("In get num files")
	loc := userdata.Numfiles_addr
	a, ok := userlib.DatastoreGet(loc)
	if !ok {
		return -9999977
	}

	if len(a) <= 32 {
		return -10008
	}
	message_mac := a[len(a)-32:]
	message := a[:len(a)-32]
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(message)
	expected_mac := mac.Sum(nil)
	if userlib.Equal(expected_mac, message_mac) {
		json.Unmarshal(message, &f)
		userlib.DebugMsg("Num*files %v", f)
		return f
	}
	return -10008
}
func incNumFiles(userdata *User) error {
	userlib.DebugMsg("In inc num files")
	loc := userdata.Numfiles_addr
	a, ok := userlib.DatastoreGet(loc)
	if !ok {
		return errors.New("error get")
	}
	if len(a) <= 32 {
		return errors.New("in num authenticity")
	}
	message_mac := a[len(a)-32:]
	message := a[:len(a)-32]
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(message)
	expected_mac := mac.Sum(nil)
	if userlib.Equal(expected_mac, message_mac) {
		var f int
		json.Unmarshal(message, &f)
		new_no := f + 1
		userlib.DebugMsg("$$$ value $$$ %v", new_no)
		a, err := json.Marshal(new_no)
		if err != nil {
			return err
		}
		mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
		mac.Write(a)
		userlib.DatastoreSet(loc, append(a, mac.Sum(nil)...))
		return nil
	}
	return errors.New("in num authenticity")
}

func decNumFiles(userdata *User) error {
	userlib.DebugMsg("In dec num files")
	loc := userdata.Numfiles_addr
	a, ok := userlib.DatastoreGet(loc)
	if !ok {
		return errors.New("error get")
	}
	if len(a) <= 32 {
		return errors.New("in num authenticity")
	}
	message_mac := a[len(a)-32:]
	message := a[:len(a)-32]
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(message)
	expected_mac := mac.Sum(nil)
	if userlib.Equal(expected_mac, message_mac) {
		var f int
		json.Unmarshal(message, &f)
		new_no := f - 1
		a, err := json.Marshal(new_no)
		if err != nil {
			return err
		}
		mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
		mac.Write(a)
		userlib.DatastoreSet(loc, append(a, mac.Sum(nil)...))
		return nil
	}
	return errors.New("in num authenticity")
}

func getNumBlocks(fileinode FileInode) (f int) {
	userlib.DebugMsg("In get num blocks")

	loc := fileinode.Num_blocks_addr
	a, ok := userlib.DatastoreGet(loc)
	if !ok {
		return -9999977
	}

	if len(a) <= 32 {
		return -10008
	}
	message_mac := a[len(a)-32:]
	message := a[:len(a)-32]
	mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
	mac.Write(message)
	expected_mac := mac.Sum(nil)
	if userlib.Equal(expected_mac, message_mac) {
		json.Unmarshal(message, &f)
		userlib.DebugMsg("Num*bocks %v", f)
		return f
	}
	return -10008
}
func incNumBlocks(fileinode FileInode) error {
	userlib.DebugMsg("In inc num blocks")
	loc := fileinode.Num_blocks_addr
	a, ok := userlib.DatastoreGet(loc)
	if !ok {
		return errors.New("error get")
	}
	if len(a) <= 32 {
		return errors.New("in num authenticity")
	}
	message_mac := a[len(a)-32:]
	message := a[:len(a)-32]
	mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
	mac.Write(message)
	expected_mac := mac.Sum(nil)
	if userlib.Equal(expected_mac, message_mac) {
		var f int
		json.Unmarshal(message, &f)
		new_no := f + 1
		userlib.DebugMsg("$$$ value $$$ %v", new_no)
		a, err := json.Marshal(new_no)
		if err != nil {
			return err
		}
		mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
		mac.Write(a)
		userlib.DatastoreSet(loc, append(a, mac.Sum(nil)...))
		return nil
	}
	return errors.New("in num authenticity")
}

func decNumBlocks(fileinode FileInode) error {
	userlib.DebugMsg("In dec num blocks")
	loc := fileinode.Num_blocks_addr
	a, ok := userlib.DatastoreGet(loc)
	if !ok {
		return errors.New("error get")
	}
	if len(a) <= 32 {
		return errors.New("in num authenticity")
	}
	message_mac := a[len(a)-32:]
	message := a[:len(a)-32]
	mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
	mac.Write(message)
	expected_mac := mac.Sum(nil)
	if userlib.Equal(expected_mac, message_mac) {
		var f int
		json.Unmarshal(message, &f)
		new_no := f + 1
		userlib.DebugMsg("$$$ value $$$ %v", new_no)
		a, err := json.Marshal(new_no)
		if err != nil {
			return err
		}
		mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
		mac.Write(a)
		userlib.DatastoreSet(loc, append(a, mac.Sum(nil)...))
		return nil
	}
	return errors.New("in num authenticity")
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	//f := uuid.New()
	//userlib.DebugMsg("UUID as string:%v", f.String())
	//userdata.Username = username
	//userdata.Password = password
	//userdata.Numfiles = 0
	//userdata.MasterInode = string(userlib.RandomBytes(16))     // TODO change!!
	userdata.MasterInode = uuid.New().String()
	userdata.HMAC_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	userdata.AES_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))

	userdata.Numfiles_addr = uuid.New().String()
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(intToByte(0))
	userlib.DatastoreSet(userdata.Numfiles_addr, append(intToByte(0), mac.Sum(nil)...))

	var uuid_len uint32
	uuid_len = 16
	//userStructLocation := string(userlib.Argon2Key([]byte(password), []byte(username), uuid_len)[:uuid_len])
	userStructLocation := hex.EncodeToString(userlib.Argon2Key([]byte(password), []byte(username), uuid_len)[:uuid_len])

	key, errk := userlib.GenerateRSAKey()
	if errk != nil {
		var a User
		return &a, errk
	}
	userdata.Private_key = key
	public_key := key.PublicKey
	// storing the public_key at username location so that everyone can see it
	userlib.KeystoreSet(username, public_key)

	random1 := userlib.RandomBytes(int(uuid_len))
	random2 := userlib.RandomBytes(int(uuid_len))

	block_size := userlib.BlockSize
	AES_key := userlib.Argon2Key([]byte(password), random1, uint32(userlib.AESKeySize))
	HMAC_key := userlib.Argon2Key([]byte(password), random2, uint32(userlib.AESKeySize))

	userdata_bytes, err := json.Marshal(userdata)
	if err != nil {
		var a User
		return &a, err
	}

	var encrypted_userdata = make([]byte, len(userdata_bytes))
	var iv = make([]byte, block_size)

	stream := userlib.CFBEncrypter(AES_key, iv)
	stream.XORKeyStream(encrypted_userdata, userdata_bytes)
	ciphertext := append(append(random1, random2...), encrypted_userdata...)
	mac = userlib.NewHMAC(HMAC_key)
	mac.Write(ciphertext)
	// userlib.DebugMsg("[DEBUG] temp is %v %v", mac.Sum(nil), len(mac.Sum(nil)))
	userlib.DatastoreSet(userStructLocation, append(ciphertext, mac.Sum(nil)...))

	// userlib.DebugMsg("userdata_bytes is %v", userdata)
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	//UserStructLocation := (userlib.Argon2Key([]byte(password), []byte(username), 16))
	UserStructLocation := hex.EncodeToString(userlib.Argon2Key([]byte(password), []byte(username), 16)[:16])
	message, ok := userlib.DatastoreGet(UserStructLocation)
	var g User
	if ok {
		if len(message) <= 32 {
			var temp User
			return &temp, errors.New("slice error")
		}
		message_mac := message[len(message)-32:]
		message_cipher := message[:len(message)-32]
		if len(message_cipher) <= 32 {
			var temp User
			return &temp, errors.New("slice error")
		}
		random1 := message_cipher[:16]
		random2 := message_cipher[16:32]
		message_encrypted_userdata := message_cipher[32:]
		AES_key := userlib.Argon2Key([]byte(password), random1, 16)
		HMAC_key := userlib.Argon2Key([]byte(password), random2, 16)

		mac := userlib.NewHMAC(HMAC_key)
		mac.Write(message_cipher)
		expected_mac := mac.Sum(nil)
		if userlib.Equal(expected_mac, message_mac) {
			var iv = make([]byte, 16)
			var userdata_bytes = make([]byte, len(message_encrypted_userdata))
			stream := userlib.CFBDecrypter(AES_key, iv)
			stream.XORKeyStream(userdata_bytes, message_encrypted_userdata)
			var g User
			json.Unmarshal(userdata_bytes, &g)
			//if g.Username != username || g.Password != password {
			//var h User
			//return &h, errors.New("username password mismatch in userstruct")
			//}
			tempstr := []byte("To test authenticity")
			PrivateKey, _ := userlib.KeystoreGet(username)
			message, _ := userlib.RSAEncrypt(&PrivateKey, tempstr, nil)
			ret, err := userlib.RSADecrypt(g.Private_key, message, nil)
			userlib.DebugMsg("***NONCE %v %v", string(tempstr), string(ret))
			if err != nil || string(ret) != string(tempstr) {
				var h User
				return &h, errors.New("nonce fail")
			}

			//userlib.DebugMsg("Unmashaled data %v", g)
			return &g, nil
		} else {
			return &g, errors.New("Corrupted!")
		}
	} else {

		return &g, errors.New("Bad username/password ")
	}
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!

func get_file_inode(userdata *User, filename string) (fileinode FileInode, err error) {
	// TODO store file inode size separately in a structure and need to check if total buffer size is a multiple of this size
	// Return if it is not. If it is multiple, very less chance for adversary to actually get same checksum and hence the method is secure
	userlib.DebugMsg("Num files ****### %v", getNumFiles(userdata))
	userlib.DebugMsg("userdata num files location %v", userdata.Numfiles_addr)
	master_inode := userdata.MasterInode
	//encrypted_master_inode, _ := userlib.DatastoreGet(master_inode)
	userlib.DebugMsg("IN get_file_inode")
	message, errm := userlib.DatastoreGet(master_inode)
	userlib.DebugMsg("Master Inode %v", []byte(master_inode))
	if errm != true {
		var file FileInode
		return file, errors.New("MasterInode not initialised")
	}

	userlib.DebugMsg("DEBUG")
	//check whether there are any files to load/append from/to
	if getNumFiles(userdata) < 0 {
		var file FileInode
		return file, errors.New("get file error")
	}
	if len(message) == 0 || getNumFiles(userdata) == 0 { // second case can occur in revoke append!!
		var file FileInode
		userlib.DebugMsg("ppppp len message %v num files %v", len(message), getNumFiles(userdata))
		return file, errors.New("No files exist")
	}
	if len(message) <= 32 {
		var file FileInode
		return file, errors.New("Slice error")
	}
	message_cipher := message[:len(message)-32]
	message_mac := message[len(message)-32:]
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(message_cipher)
	expected_mac := mac.Sum(nil)
	var master_inode_bytes []byte
	if userlib.Equal(expected_mac, message_mac) {
		var iv = make([]byte, 16)
		master_inode_bytes = make([]byte, len(message_cipher))
		stream := userlib.CFBDecrypter([]byte(userdata.AES_key), iv)
		stream.XORKeyStream(master_inode_bytes, message_cipher)
	} else {
		var file FileInode
		return file, errors.New("Master Inode Integrity Fail")
	}
	//var fileinode = FileInode{}
	//fileinode_size := len(master_inode_bytes) / userdata.Numfiles
	if getNumFiles(userdata) == 0 {
		var file FileInode
		return file, errors.New("Division error")
	}
	if len(master_inode_bytes)%getNumFiles(userdata) != 0 {
		var file FileInode
		return file, errors.New("Division error")
	}
	fileinode_size := len(master_inode_bytes) / getNumFiles(userdata)
	if len(master_inode_bytes)%fileinode_size != 0 {
		var file FileInode
		return file, errors.New("Division error")
	}
	for i := 0; i < len(master_inode_bytes); i += fileinode_size {
		var temp FileInode
		file_bytes := master_inode_bytes[i:(i + fileinode_size)]
		json.Unmarshal(file_bytes, &temp)
		h := userlib.NewSHA256()
		h.Write([]byte(filename))
		filename_hash := h.Sum(nil)
		if hex.EncodeToString(filename_hash) == temp.Filename {
			fileinode = temp
			userlib.DebugMsg("Same hash")
		}
	}
	//userlib.DebugMsg("fileinode %v", fileinode)
	return fileinode, nil
}

func (userdata *User) StoreFile(filename string, data []byte) {
	var fileinode FileInode
	h := userlib.NewSHA256()
	h.Write([]byte(filename))
	filename_hash := h.Sum(nil)
	fileinode.Filename = hex.EncodeToString(filename_hash)
	// userlib.DebugMsg("FileInode Authenticity : %v", len(filename_hash))
	//fileinode.Location = bytesToUUID(userlib.RandomBytes(16))
	fileinode.Location = uuid.New().String() // need to marshal each such string to convert to bytes!
	//fileinode.HMAC_key = string(userlib.RandomBytes(userlib.AESKeySize))
	fileinode.HMAC_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	fileinode.AES_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	//fileinode.AES_key = string(userlib.RandomBytes(userlib.AESKeySize))
	fileinode.Num_blocks_addr = uuid.New().String()

	temp_fileinode, errg := get_file_inode(userdata, filename)
	userlib.DebugMsg("errg ####################################### %v %v", temp_fileinode, errg)
	if errg == nil && temp_fileinode != (FileInode{}) {
		userlib.DebugMsg("file found")
		fileinode.Location = temp_fileinode.Location
		fileinode.AES_key = temp_fileinode.AES_key
		fileinode.HMAC_key = temp_fileinode.HMAC_key
		fileinode.Num_blocks_addr = temp_fileinode.Num_blocks_addr
		//decNumFiles(userdata)
	}
	//if errg != nil && errg != errors.New("MasterInode not initialised") {
	//return
	//}

	mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
	mac.Write(intToByte(1))
	userlib.DatastoreSet(fileinode.Num_blocks_addr, append(intToByte(1), mac.Sum(nil)...))

	fileinode_bytes, err := json.Marshal(fileinode)
	if err != nil {
		return
	}

	var master_inode_bytes []byte
	master_inode := userdata.MasterInode
	//if userdata.Numfiles != 0 {
	if getNumFiles(userdata) != 0 {
		message, ok := userlib.DatastoreGet(master_inode)
		if !ok {
			return
		}
		if len(message) <= 32 {
			return
		}
		message_cipher := message[:len(message)-32]
		message_mac := message[len(message)-32:]
		mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
		mac.Write(message_cipher)
		expected_mac := mac.Sum(nil)
		if userlib.Equal(expected_mac, message_mac) {
			var iv = make([]byte, 16)
			master_inode_bytes = make([]byte, len(message_cipher))
			stream := userlib.CFBDecrypter([]byte(userdata.AES_key), iv)
			stream.XORKeyStream(master_inode_bytes, message_cipher)
		} else {
			//var file FileInode
			userlib.DebugMsg("FileInode Authenticity")
			// TODO what should we do if fileInode structure is corrupt. Individual files may not be harmed byt overall structure is?? Should we maintain per file integrity
			//return file, errors.New("Master Inode Integrity Fail")
		}
	}

	master_inode_bytes = append(master_inode_bytes, fileinode_bytes...)
	var encrypted_master_inode = make([]byte, len(master_inode_bytes))
	var iv = make([]byte, userlib.BlockSize)
	stream := userlib.CFBEncrypter([]byte(userdata.AES_key), iv)
	stream.XORKeyStream(encrypted_master_inode, master_inode_bytes)

	mac = userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(encrypted_master_inode)
	checksum := mac.Sum(nil)
	userlib.DatastoreSet(master_inode, append(encrypted_master_inode, checksum...))

	var file_block FileStruct
	//file_block.Block_num = 0
	file_block.Location = uuid.New().String()
	file_block.HMAC_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	file_block.AES_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	//file_block.Size = len(data)

	var encrypted_filedata = make([]byte, len(data))
	//var iv = make([]byte, userlib.BlockSize)
	stream = userlib.CFBEncrypter([]byte(file_block.AES_key), iv)
	stream.XORKeyStream(encrypted_filedata, data)

	mac = userlib.NewHMAC([]byte(file_block.HMAC_key))
	mac.Write(encrypted_filedata)
	checksum = mac.Sum(nil)
	userlib.DebugMsg("DATA %v", string(data))

	userlib.DatastoreSet(file_block.Location, append(encrypted_filedata, checksum...))
	file_block_bytes, err := json.Marshal(file_block)
	if err != nil {
		return
	}
	var encrypted_file_block = make([]byte, len(file_block_bytes))
	//var iv = make([]byte, userlib.BlockSize)
	// TODO use decode string in aes etc
	stream = userlib.CFBEncrypter([]byte(fileinode.AES_key), iv)
	stream.XORKeyStream(encrypted_file_block, file_block_bytes)

	mac = userlib.NewHMAC([]byte(fileinode.HMAC_key))
	mac.Write(encrypted_file_block)
	checksum = mac.Sum(nil)

	userlib.DatastoreSet(fileinode.Location, append(encrypted_file_block, checksum...))
	//userdata.Numfiles += 1
	incNumFiles(userdata)

	userlib.DebugMsg("%v here here", getNumFiles(userdata))

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func update_file_inode(userdata *User, filename string, fileinode FileInode) (err error) {
	master_inode := userdata.MasterInode
	message, ok := userlib.DatastoreGet(master_inode)
	if ok != true {
		return errors.New("Master Inode Corrupted")
	}
	if len(message) <= 32 {
		return errors.New("Slice error")
	}
	message_cipher := message[:len(message)-32]
	message_mac := message[len(message)-32:]
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(message_cipher)
	expected_mac := mac.Sum(nil)
	var master_inode_bytes []byte
	if userlib.Equal(expected_mac, message_mac) {
		var iv = make([]byte, 16)
		master_inode_bytes = make([]byte, len(message_cipher))
		stream := userlib.CFBDecrypter([]byte(userdata.AES_key), iv)
		stream.XORKeyStream(master_inode_bytes, message_cipher)
	} else {
		return errors.New("Master Inode Integrity Fail")
	}
	//master_inode_bytes, _ := userlib.DatastoreGet(master_inode)
	//fileinode_size := len(master_inode_bytes) / userdata.Numfiles
	if getNumFiles(userdata) < 0 {
		return errors.New("get file error")
	}
	if getNumFiles(userdata) == 0 {
		return errors.New("Division error")
	}
	if len(master_inode_bytes)%getNumFiles(userdata) != 0 {
		return errors.New("Division error")
	}
	fileinode_size := len(master_inode_bytes) / getNumFiles(userdata)
	if len(master_inode_bytes)%fileinode_size != 0 {
		return errors.New("Division error")
	}
	for i := 0; i < len(master_inode_bytes); i += fileinode_size {
		var temp FileInode
		file_bytes := master_inode_bytes[i:(i + fileinode_size)]
		json.Unmarshal(file_bytes, &temp)
		h := userlib.NewSHA256()
		h.Write([]byte(filename))
		filename_hash := h.Sum(nil)
		if hex.EncodeToString(filename_hash) == temp.Filename {
			userlib.DebugMsg("Updating Inode")

			fileinode_bytes, err := json.Marshal(fileinode)
			if err != nil {
				return err
			}
			userlib.DebugMsg("filnode size: %v", fileinode_size)
			userlib.DebugMsg("filnode bytes: %v", len(fileinode_bytes))
			for j := 0; j < fileinode_size; j++ {
				master_inode_bytes[i+j] = fileinode_bytes[j]
			}
		}
	}
	var encrypted_master_inode = make([]byte, len(master_inode_bytes))
	var iv = make([]byte, userlib.BlockSize)
	stream := userlib.CFBEncrypter([]byte(userdata.AES_key), iv)
	stream.XORKeyStream(encrypted_master_inode, master_inode_bytes)

	mac = userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(encrypted_master_inode)
	checksum := mac.Sum(nil)
	userlib.DatastoreSet(master_inode, append(encrypted_master_inode, checksum...))

	//userlib.DatastoreSet(master_inode, master_inode_bytes)
	return nil
}

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileinode, err := get_file_inode(userdata, filename)
	if err != nil {
		return err
	}
	if fileinode == (FileInode{}) {
		return errors.New("No such filename exists for the user")
	}
	// integrity checks not necessary!
	file_bytes, ok := userlib.DatastoreGet(fileinode.Location)
	if ok != true {
		return errors.New("File Location Not found")
	}
	userlib.DebugMsg("[In Append] File bytes: %v", len(file_bytes))
	userlib.DebugMsg("file block size 2: %v", len(file_bytes))
	userlib.DebugMsg("Num blocks**: %v", getNumBlocks(fileinode))
	//fileinode.Num_blocks += 1
	errr := incNumBlocks(fileinode)
	if errr != nil {
		return errr
	}
	userlib.DebugMsg("Num blocks**: %v", getNumBlocks(fileinode))
	var file_block FileStruct
	//file_block.Block_num += 1
	file_block.Location = uuid.New().String()
	file_block.HMAC_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	file_block.AES_key = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))
	//file_block.Size = len(data)

	var encrypted_filedata = make([]byte, len(data))
	var iv = make([]byte, userlib.BlockSize)
	stream := userlib.CFBEncrypter([]byte(file_block.AES_key), iv)
	stream.XORKeyStream(encrypted_filedata, data)

	mac := userlib.NewHMAC([]byte(file_block.HMAC_key))
	mac.Write(encrypted_filedata)
	checksum := mac.Sum(nil)

	userlib.DatastoreSet(file_block.Location, append(encrypted_filedata, checksum...))

	file_block_bytes, err := json.Marshal(file_block)
	if err != nil {
		return err
	}
	userlib.DebugMsg("[In Append] File bytes2: %v", len(file_block_bytes))
	var encrypted_file_block = make([]byte, len(file_block_bytes))
	//var iv = make([]byte, userlib.BlockSize)
	// TODO use decode string in aes etc
	// TODO same key for all file appends!!! Security issue? Adversary can guess??
	stream = userlib.CFBEncrypter([]byte(fileinode.AES_key), iv)
	stream.XORKeyStream(encrypted_file_block, file_block_bytes)

	mac = userlib.NewHMAC([]byte(fileinode.HMAC_key))
	mac.Write(encrypted_file_block)
	checksum = mac.Sum(nil)
	userlib.DebugMsg("[In Append] File bytes1: %v", len(file_bytes))
	file_bytes = append(file_bytes, append(encrypted_file_block, checksum...)...)

	userlib.DatastoreSet(fileinode.Location, file_bytes)
	err = update_file_inode(userdata, filename, fileinode)
	if err != nil {
		userlib.DebugMsg("In append master inode integrity fail")
	}
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO Store files from different test functions not visible
	fileinode, err := get_file_inode(userdata, filename)
	if err != nil {
		var a []byte
		return a, err
	}
	if fileinode == (FileInode{}) {
		var a []byte
		return a, errors.New("No such filename exists for the user")
	}

	// TODO decrypt

	file_bytes, ok := userlib.DatastoreGet(fileinode.Location)
	if ok != true {
		var a []byte
		return a, errors.New("File Location Not found")
	}
	if getNumBlocks(fileinode) < 0 {
		var a []byte
		return a, errors.New("get block error")
	}
	if getNumBlocks(fileinode) == 0 {
		var a []byte
		return a, errors.New("Division error")
	}
	if len(file_bytes)%getNumBlocks(fileinode) != 0 {
		var a []byte
		return a, errors.New("Division error")
	}
	file_block_size := len(file_bytes) / getNumBlocks(fileinode)
	if len(file_bytes)%file_block_size != 0 {
		var a []byte
		return a, errors.New("Division error")
	}
	userlib.DebugMsg("File block size: %v", file_block_size)
	userlib.DebugMsg("Num blocks: %v", getNumBlocks(fileinode))
	userlib.DebugMsg("File bytes: %v", len(file_bytes))
	var output_buffer []byte
	for i := 0; i < len(file_bytes); i += file_block_size {
		userlib.DebugMsg("************")
		message := file_bytes[i:(i + file_block_size)]
		if len(message) <= 32 {
			var temp []byte
			return temp, errors.New("Slice error")
		}
		message_cipher := message[:len(message)-32]
		message_mac := message[len(message)-32:]
		mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
		mac.Write(message_cipher)
		expected_mac := mac.Sum(nil)
		if userlib.Equal(expected_mac, message_mac) {
			userlib.DebugMsg("mac ok")
			var iv = make([]byte, 16)
			var file_block_bytes = make([]byte, len(message_cipher))
			stream := userlib.CFBDecrypter([]byte(fileinode.AES_key), iv)
			stream.XORKeyStream(file_block_bytes, message_cipher)
			var file_block FileStruct
			json.Unmarshal(file_block_bytes, &file_block)
			message, ok := userlib.DatastoreGet(file_block.Location)
			if ok != true {
				var a []byte
				return a, errors.New("File block Location Not found")
			}

			if len(message) <= 32 {
				var temp []byte
				return temp, errors.New("Slice error")
			}
			message_cipher := message[:len(message)-32]
			message_mac := message[len(message)-32:]
			mac := userlib.NewHMAC([]byte(file_block.HMAC_key))
			mac.Write(message_cipher)
			expected_mac := mac.Sum(nil)
			if userlib.Equal(expected_mac, message_mac) {
				userlib.DebugMsg("Data Integrity ok")
				var iv = make([]byte, 16)
				var data_block_bytes = make([]byte, len(message_cipher))
				stream := userlib.CFBDecrypter([]byte(file_block.AES_key), iv)
				stream.XORKeyStream(data_block_bytes, message_cipher)
				output_buffer = append(output_buffer, data_block_bytes...)
				userlib.DebugMsg("Returned %v", string(data_block_bytes))
				//return data_block_bytes, nil
			} else {
				var a []byte
				return a, errors.New("Data Integirty Error")
			}

		} else {
			var a []byte
			return a, errors.New("Block corrupt")
		}
	}
	userlib.DebugMsg("Returned 2 %v", string(output_buffer))
	return output_buffer, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	fileinode, err := get_file_inode(userdata, filename)
	if err != nil {
		var a string
		return a, err
	}
	if fileinode == (FileInode{}) {
		var a string
		return a, errors.New("No such filename exists for the user")
	}
	//TODO encrypt FileInode struct with recipient's public key

	//Get recipient's public key
	rec_pub_key, ok := userlib.KeystoreGet(recipient)
	if ok != true {
		var a string
		return a, errors.New("User doesn't exist")
	}
	// userlib.DebugMsg("SHAREFILE rec_pub_key %v", rec_pub_key)
	// userlib.DebugMsg("SHARED FILE %v", fileinode)
	fileinode_bytes, err := json.Marshal(fileinode)
	if err != nil {
		var a string
		return a, errors.New("Marshal Error")
	}
	encrypted_fileinode := make([]byte, 0)
	userlib.DebugMsg("SHAREFILE length %v", len(fileinode_bytes))

	for i := 0; i < len(fileinode_bytes)/190+1; i++ {
		var temp_encrypted_fileinode []byte
		var err2 error
		//nil is used as tag to encrypt fileinode
		if i == len(fileinode_bytes)/190 {
			temp_encrypted_fileinode, err2 = userlib.RSAEncrypt(&rec_pub_key, fileinode_bytes[i*190:], nil)
		} else {
			temp_encrypted_fileinode, err2 = userlib.RSAEncrypt(&rec_pub_key, fileinode_bytes[i*190:(i+1)*190], nil)
		}
		if err2 != nil {
			var a string
			return a, err2
		}
		encrypted_fileinode = append(encrypted_fileinode, temp_encrypted_fileinode...)
	}
	//TODO calc and append mac of encrypted filenode append to msgid
	//mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
	//mac.Write(encrypted_fileinode)
	//checksum := mac.Sum(nil)
	//encrypted_fileinode = append(encrypted_fileinode, checksum...)

	//TODO sign with sender's private key
	sign, err3 := userlib.RSASign(userdata.Private_key, encrypted_fileinode)
	if err3 != nil {
		var a string
		return a, err3
	}
	encrypted_fileinode = append(encrypted_fileinode, sign...)
	//encrypted_fileinode now contains: encrypted(fileinode_bytes) | checksum[32] | sign[256]
	userlib.DebugMsg("SHAREFILE encrypted_fileinode %v", len(encrypted_fileinode))

	// userlib.DebugMsg("SHAREFILE encrypted_fileinode %v", len(encrypted_fileinode))
	return string(encrypted_fileinode), nil
}

func StoreReceivedFile(userdata *User, fileinode FileInode) error {
	fileinode_bytes, errr := json.Marshal(fileinode)
	if errr != nil {
		return errr
	}

	var master_inode_bytes []byte
	master_inode := userdata.MasterInode
	if getNumFiles(userdata) < 0 {
		return errors.New("get file error")
	}
	if getNumFiles(userdata) != 0 {
		message, ok := userlib.DatastoreGet(master_inode)
		if ok != true {
			return errors.New("MasterInode Location Not found")
		}

		if len(message) <= 32 {
			return errors.New("Slice error")
		}
		message_cipher := message[:len(message)-32]
		message_mac := message[len(message)-32:]
		mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
		mac.Write(message_cipher)
		expected_mac := mac.Sum(nil)
		if userlib.Equal(expected_mac, message_mac) {
			var iv = make([]byte, 16)
			master_inode_bytes = make([]byte, len(message_cipher))
			stream := userlib.CFBDecrypter([]byte(userdata.AES_key), iv)
			stream.XORKeyStream(master_inode_bytes, message_cipher)
		} else {
			//var file FileInode
			// userlib.DebugMsg("FileInode Authenticity")
			// TODO what should we do if fileInode structure is corrupt. Individual files may not be harmed byt overall structure is?? Should we maintain per file integrity
			return errors.New("Master Inode Integrity Fail")
		}
	}

	master_inode_bytes = append(master_inode_bytes, fileinode_bytes...)
	var encrypted_master_inode = make([]byte, len(master_inode_bytes))
	var iv = make([]byte, userlib.BlockSize)
	stream := userlib.CFBEncrypter([]byte(userdata.AES_key), iv)
	stream.XORKeyStream(encrypted_master_inode, master_inode_bytes)

	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(encrypted_master_inode)
	checksum := mac.Sum(nil)
	userlib.DatastoreSet(master_inode, append(encrypted_master_inode, checksum...))

	//userdata.Numfiles += 1
	err := incNumFiles(userdata)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("RECIEVED FILE %v", fileinode)
	return nil

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	if len(msgid) == 0 {
		return errors.New("No file shared")
	}
	if len(msgid) < 256 || len(msgid)%256 != 0 {
		return errors.New("message length error")
	}
	recv_sign := []byte(msgid[len(msgid)-256:])
	userlib.DebugMsg("RECIEVEFILE encrypted_fileinode %v", len(recv_sign))
	//recv_checksum := []byte(msgid[len(msgid)-256-0 : len(msgid)-256])
	//userlib.DebugMsg("RECIEVEFILE encrypted_fileinode %v", len(recv_checksum))
	recv_encrypted_fileinode := []byte(msgid[:len(msgid)-256-0])
	userlib.DebugMsg("RECIEVEFILE encrypted_fileinode %v", len(recv_encrypted_fileinode))
	//TODO verify sign
	sender_pub_key, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("Sender Invalid")
	}
	err := userlib.RSAVerify(&sender_pub_key, []byte(msgid[:len(msgid)-256]), recv_sign)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("ERROR_MSG %v", err)

	//TODO decrypt
	//NOTE If we end up removing username from userstruct then tag needs to be changed
	var decrypted_fileinode []byte
	if len(recv_encrypted_fileinode)%256 != 0 {
		return errors.New("share length erro")
	}
	for i := 0; i < len(recv_encrypted_fileinode)/256; i++ {
		var temp_decrypted_fileinode []byte
		temp_decrypted_fileinode, err2 := userlib.RSADecrypt(userdata.Private_key, recv_encrypted_fileinode[i*256:(i+1)*256], nil)
		// userlib.DebugMsg("decrypt: %v, %v", temp_decrypted_fileinode, err2)
		if err2 != nil {
			return err2
		}
		decrypted_fileinode = append(decrypted_fileinode, temp_decrypted_fileinode...)
	}
	// userlib.DebugMsg("decrypted_fileinode: %v", decrypted_fileinode)
	var fileinode FileInode
	json.Unmarshal(decrypted_fileinode, &fileinode)
	// userlib.DebugMsg("RECIEVED FILE %v", fileinode)

	//TODO verify integrity
	//mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
	//mac.Write(recv_encrypted_fileinode)
	//checksum := mac.Sum(nil)
	//if userlib.Equal(checksum, recv_checksum) {
	//userlib.DebugMsg("Data Integirty OK!")
	//} else {
	//return errors.New("Data Integirty Error")
	//}

	//TODO change filename hash
	h := userlib.NewSHA256()
	h.Write([]byte(filename))
	filename_hash := h.Sum(nil)
	fileinode.Filename = hex.EncodeToString(filename_hash)
	temp_fileinode, errg := get_file_inode(userdata, filename)
	userlib.DebugMsg("errg ####################################### %v %v", temp_fileinode, errg)
	if errg == nil && temp_fileinode != (FileInode{}) {
		userlib.DebugMsg("file found")
		fileinode.Location = temp_fileinode.Location
		fileinode.AES_key = temp_fileinode.AES_key
		fileinode.HMAC_key = temp_fileinode.HMAC_key
		fileinode.Num_blocks_addr = temp_fileinode.Num_blocks_addr
		//decNumFiles(userdata)
	}

	//TODO get the masterInode, decrypt it, add fileinode to it, then encrypt it again
	err3 := StoreReceivedFile(userdata, fileinode)
	if err3 != nil {
		return err3
	}
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	//TODO get file data from loadfile
	data, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	userlib.DebugMsg("DATA: %v", data)

	//TODO get masterInode, decrypt it, verify integrity
	master_inode := userdata.MasterInode
	message, ok := userlib.DatastoreGet(master_inode)
	if ok != true {
		return errors.New("MasterInode Location Not found")
	}
	if len(message) <= 32 {
		return errors.New("Slice error")
	}
	message_cipher := message[:len(message)-32]
	message_mac := message[len(message)-32:]
	mac := userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(message_cipher)
	expected_mac := mac.Sum(nil)
	var master_inode_bytes []byte
	if userlib.Equal(expected_mac, message_mac) {
		var iv = make([]byte, 16)
		master_inode_bytes = make([]byte, len(message_cipher))
		stream := userlib.CFBDecrypter([]byte(userdata.AES_key), iv)
		stream.XORKeyStream(master_inode_bytes, message_cipher)
	} else {
		return errors.New("Master Inode Integrity Fail")
	}

	var new_master_inode_bytes []byte
	if getNumFiles(userdata) < 0 {
		return errors.New("get file error")
	}
	if getNumFiles(userdata) == 0 {
		return errors.New("Division error")
	}
	if len(master_inode_bytes)%getNumFiles(userdata) != 0 {
		return errors.New("Division error")
	}
	fileinode_size := len(master_inode_bytes) / getNumFiles(userdata)
	if len(master_inode_bytes)%fileinode_size != 0 {
		return errors.New("Division error")
	}
	for i := 0; i < len(master_inode_bytes); i += fileinode_size {
		var temp FileInode
		file_bytes := master_inode_bytes[i:(i + fileinode_size)]
		json.Unmarshal(file_bytes, &temp)
		h := userlib.NewSHA256()
		h.Write([]byte(filename))
		filename_hash := h.Sum(nil)
		if hex.EncodeToString(filename_hash) == temp.Filename {
			userlib.DebugMsg("Found the file")
			//clear contents in temp
			var fileinode = temp
			file_bytes, ok := userlib.DatastoreGet(fileinode.Location)
			if ok != true {
				return errors.New("File Location Not found")
			}
			if getNumBlocks(fileinode) < 0 {
				return errors.New("get block error")
			}
			if getNumBlocks(fileinode) == 0 {
				return errors.New("Division error")
			}
			if len(file_bytes)%getNumBlocks(fileinode) != 0 {
				return errors.New("Division error")
			}
			file_block_size := len(file_bytes) / getNumBlocks(fileinode)
			if len(file_bytes)%file_block_size != 0 {
				return errors.New("Division error")
			}
			for i := 0; i < len(file_bytes); i += file_block_size {
				message := file_bytes[i:(i + file_block_size)]
				if len(message) <= 32 {
					return errors.New("Slice error")
				}
				message_cipher := message[:len(message)-32]
				message_mac := message[len(message)-32:]
				mac := userlib.NewHMAC([]byte(fileinode.HMAC_key))
				mac.Write(message_cipher)
				expected_mac := mac.Sum(nil)
				if userlib.Equal(expected_mac, message_mac) {
					var iv = make([]byte, 16)
					var file_block_bytes = make([]byte, len(message_cipher))
					stream := userlib.CFBDecrypter([]byte(fileinode.AES_key), iv)
					stream.XORKeyStream(file_block_bytes, message_cipher)
					var file_block FileStruct
					json.Unmarshal(file_block_bytes, &file_block)
					userlib.DatastoreDelete(file_block.Location)
				} else {
					return errors.New("Block corrupt")
				}
			}

			userlib.DatastoreDelete(temp.Location)

			fileinode_bytes, err := json.Marshal(temp)
			if err != nil {
				return err
			}
			userlib.DebugMsg("FileInode: %v", fileinode_bytes)
			userlib.DebugMsg("original master inode: %v", []byte(master_inode_bytes))
			userlib.DebugMsg("file_inode_size: %v", []byte(master_inode_bytes))
			//Delete filename from masterInode
			new_master_inode_bytes = append(master_inode_bytes[:i], master_inode_bytes[i+fileinode_size:]...)
			userlib.DebugMsg("MasterInode: %v", new_master_inode_bytes)
			//userdata.Numfiles -= 1
			err = decNumFiles(userdata)
			if err != nil {
				return err
			}
		}
	}
	//Update the MasterInode
	var encrypted_master_inode = make([]byte, len(new_master_inode_bytes))
	var iv = make([]byte, userlib.BlockSize)
	stream := userlib.CFBEncrypter([]byte(userdata.AES_key), iv)
	stream.XORKeyStream(encrypted_master_inode, new_master_inode_bytes)

	mac = userlib.NewHMAC([]byte(userdata.HMAC_key))
	mac.Write(encrypted_master_inode)
	checksum := mac.Sum(nil)
	userlib.DatastoreSet(master_inode, append(encrypted_master_inode, checksum...))

	//TODO Create the new file
	userdata.StoreFile(filename, data)
	return nil
}
