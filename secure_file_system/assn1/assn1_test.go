package assn1

import (
	"reflect"
	"testing"

	"github.com/fenilfadadu/CS628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	//userlib.DebugPrint = true
	//	someUsefulThings()

	//userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got username", *u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	userlib.DebugPrint = false
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test ")
	u.StoreFile("file1", v)
	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
	//////
	v = []byte("This is store test 2")
	//userlib.DebugPrint = true
	u.StoreFile("file2", v)

	//mymap := userlib.DatastoreGetMap()
	//keys := make([]string, 0, len(mymap))
	//for k := range mymap {
	//keys = append(keys, k)
	//userlib.DatastoreSet(k, userlib.RandomBytes(400))
	//}
	//userlib.DebugMsg("Map %v", keys)

	v2, err2 = u.LoadFile("file2")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	//mymap = userlib.DatastoreGetMap()
	//userlib.DebugMsg("%v", mymap)
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
	v3 := []byte("This is append test ")
	v = []byte("This is a test ")
	err = u.AppendFile("file1", v3)
	v2, err2 = u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(append(v, v3...), v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

//func TestMultipleInstances(t *testing.T) {

//u, err := GetUser("alice", "fubar")
//if err != nil {
//t.Error("Failed to reload user", err)
//}
//u2, err := GetUser("alice", "fubar")
//if err != nil {
//t.Error("Failed to reload user", err)
//}
//u3, err := GetUser("alice", "fubar")
//if err != nil {
//t.Error("Failed to reload user", err)
//}

//v := []byte("This is multiple test")
//u.StoreFile("file3", v)
//v2, err2 := u2.LoadFile("file3")
//v3, err3 := u3.LoadFile("file3")
//if err2 != nil {
//t.Error("Failed to upload and download", err2)
//}
//if !reflect.DeepEqual(v, v2) {
//t.Error("Downloaded file is not the same", v, v2)
//}
//if err3 != nil {
//t.Error("Failed to upload and download", err2)
//}
//if !reflect.DeepEqual(v, v3) {
//t.Error("Downloaded file is not the same", v, v3)
//}

//}

//func TestSingleUserMultipleInstances(t *testing.T) {
//u, err := InitUser("Gandalf", "fubar")
//if err != nil {
//t.Error("ERROR: ", err)
//}
//u2, err := GetUser("Gandalf", "fubar")
//if err != nil {
//t.Error("ERROR: ", err)
//}
//u3, err := GetUser("Gandalf", "fubar")
//if err != nil {
//t.Error("ERROR: ", err)
//}
//v := []byte("Country Roads ")
//u.StoreFile("file1", v)
//f, err1 := u.LoadFile("file1")
//if err1 != nil {
//t.Error("ERROR: ", err1)
//}
//userlib.DebugMsg("A : %v", f)
//f1, err1 := u.LoadFile("file1")
//userlib.DebugMsg("f1 : %v", f1)
//if err1 != nil {
//t.Error("ERROR: ", err1)
//}
//f2, err2 := u2.LoadFile("file1")
//if err2 != nil {
//t.Error("ERROR: ", err2)
//}
//u4, err := GetUser("Gandalf", "fubar")
//if err != nil {
//t.Error("ERROR: ", err)
//}
//f4, err2 := u4.LoadFile("file1")
//if err2 != nil {
//t.Error("ERROR: ", err2)
//}

//userlib.DebugMsg("A : %v", f2)
//userlib.DebugMsg("A : %v", u3)
//userlib.DebugMsg("A : %v", f4)
//}

//func TestOtherFunc(t *testing.T) {
//u, err := GetUser("alice", "fubar")
//if err != nil {
//t.Error("Failed to reload user", err)
//}
//_, err2 := u.LoadFile("file1")
//if err2 != nil {
//t.Error("Failed to upload and download", err2)
//}
//}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}
	//u3, err3 := InitUser("eve", "foobar")
	//if err3 != nil {
	//t.Error("Failed to initialize bob", err3)
	//}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("A1 : %v", string(v))
	userlib.DebugPrint = false

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("A2 : %v", string(v2))
	userlib.DebugPrint = false

	v = []byte("This is a sharing test ")
	userlib.DebugPrint = true
	u.StoreFile("file1", v)
	userlib.DebugPrint = false
	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("A1 : %v", string(v))
	userlib.DebugPrint = false

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("A2 : %v", string(v2))
	userlib.DebugPrint = false
	//msgid, err = u.ShareFile("file2", "bob")
}

func TestRevoke(t *testing.T) {
	u, err := InitUser("Gandalf", "fubar")
	if err != nil {
		t.Error("ERROR: ", err)
	}
	v := []byte("Country Roads ")
	u.StoreFile("file1", v)

	u2, err2 := InitUser("Sauron", "fubar2")
	if err2 != nil {
		t.Error("ERROR: ", err2)
	}

	var msgid string
	msgid, err = u.ShareFile("file1", "Sauron")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "Gandalf", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	f4, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("ERROR: ", err3)
	}
	userlib.DebugPrint = false
	userlib.DebugPrint = true
	userlib.DebugMsg("A1 : %v", string(f4))
	userlib.DebugPrint = false

	v3 := []byte("Take Me Home")
	//userlib.DebugPrint = true
	err = u.AppendFile("file1", v3)
	if err != nil {
		t.Error("ERROR: ", err)
	}

	v3 = []byte(" Append check")
	err = u2.AppendFile("file2", v3)
	if err != nil {
		t.Error(err)
	}
	userlib.DebugPrint = false
	//userlib.DebugPrint = true
	f4, err3 = u.LoadFile("file1")
	if err3 != nil {
		t.Error("ERROR: ", err3)
	}
	f3, err4 := u2.LoadFile("file2")
	if err4 != nil {
		t.Error("ERROR: ", err4)
	}

	userlib.DebugPrint = true
	userlib.DebugMsg("A2 : %v", string(f3))
	userlib.DebugMsg("A2 : %v", string(f4))
	userlib.DebugPrint = false
	err = u.RevokeFile("file1")
	if err != nil {
		t.Error(err)
	}
	f4, err = u2.LoadFile("file2")
	if err != nil {
		t.Error(err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("A [revoke] : %v", string(f4))
	userlib.DebugPrint = false
	v3 = []byte(" Now")
	err = u.AppendFile("file1", v3)
	if err != nil {
		t.Error(err)
	}
	//userlib.DebugPrint = false
	f4, err = u.LoadFile("file1")
	if err != nil {
		t.Error(err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("A3 : %v", string(f4))
	userlib.DebugPrint = false
	f4, err = u2.LoadFile("file2")
	if err != nil {
		t.Error(err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("B : %v", string(f4))

	userlib.DebugPrint = false
	v3 = []byte(" Append check")
	err = u2.AppendFile("file2", v3)
	if err != nil {
		t.Error(err)
	}
	//userlib.DebugPrint = false
	f4, err = u.LoadFile("file1")
	if err != nil {
		t.Error(err)
	}
	userlib.DebugPrint = true

	userlib.DebugMsg("A3 : %v", string(f4))
	userlib.DebugPrint = false
	f4, err = u2.LoadFile("file2")
	if err != nil {
		t.Error(err)
	}
	userlib.DebugPrint = true
	userlib.DebugMsg("B : %v", string(f4))

}
