package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

// Custom tests

// test GetUser
func TestGetUser(t *testing.T) {
	clear()

	// initialize users
	u, err := InitUser("alice", "fubar")
	u2, err2 := InitUser("bob", "foobar")

	// check InitUser worked
	if err != nil {
		t.Error("Failed to initialize user alice", err)
		return
	}

	if err2 != nil {
		t.Error("Failed to initialize user bob", err2)
		return
	}

	// get users
	u1, err := GetUser("alice", "fubar")
	u21, err2 := GetUser("bob", "fubar") // this should return an error because it's the wrong password

	// check if GetUser properly got called for alice
	if err != nil {
		t.Error("GetUser on alice didn't work")
		return
	}

	// check GetUser for bob with the wrong password
	if err2 == nil {
		t.Error("GetUser shouldn't have worked")
		return
	}

	// check if right user returned for alice
	if !reflect.DeepEqual(u, u1) {
		t.Error("GetUser on alice didn't return the correct user")
		return
	}

	if reflect.DeepEqual(u2, u21) {
		t.Error("GetUser should not have returned bob")
	}

}

// test modified user
func TestModifiedUser(t *testing.T) {
	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}

	// check GetUser
	check, err := GetUser("alice", "fubar")
	if !reflect.DeepEqual(u1, check) {
		t.Error("GetUser didn't work")
		return
	}

	// file
	v := []byte("so many tests lolol")
	u1.StoreFile("file1", v)

	// test file loading
	_, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("failed to load file", err)
		return
	}

	// compromised user struct
	u1.Username = "bob"

	// test file loading (shouldn't work this time)
	_, err = u1.LoadFile("file1")
	if err == nil {
		t.Error("user struct was modified, should not have been able to load", err)
		return
	}
}

// test bad user info
func TestBadUserInfo(t *testing.T) {
	clear()

	// users
	_, err := InitUser("", "fubar")
	if err == nil {
		t.Error("Initialized with a bad username")
		return
	}
	u2, err2 := InitUser("bob", "")
	if err2 == nil {
		t.Error("Initialized with a bad password", err2)
		return
	}

	u3, err3 := InitUser("son", "tottenham")
	if err3 != nil {
		t.Error("Failed to initialize son", err3)
		return
	}

	// file
	v := []byte("tests are neverending...")
	u3.StoreFile("file1", v)

	// test file loading
	_, err = u3.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}

	// test sharing with bad users
	var magic_string string
	magic_string, err = u3.ShareFile("file1", "bob")
	if err == nil {
		t.Error("File shared with bad user")
		return
	}

	// test file loading with bad user
	err = u2.ReceiveFile("file2", "son", magic_string)
	if err == nil {
		t.Error("File received by bad user")
		return
	}
}

// test unique username
func TestUniqueUser(t *testing.T) {
	clear()

	// users
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	_, err2 := InitUser("alice", "foobar")
	if err2 == nil {
		t.Error("Initialized user with same username", err2)
		return
	}

	// test get user
	_, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	_, err = GetUser("alice", "foobar")
	if err == nil {
		t.Error("Got user that shouldn't exist")
		return
	}

}

// test file integrity after appending, then sharing
func TestAppendThenShare(t *testing.T) {
	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// file
	v1 := []byte("Katie is a cooler homie than Yifan")
	u1.StoreFile("file1", v1)

	// test file loading
	v1, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("alice's file didn't load", err)
		return
	}

	// share file
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test if file shared
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	// test if file received
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("bob didn't receive the share message", err)
		return
	}

	var v2 []byte
	v2, err2 = u2.LoadFile("file2")

	// check if file loads
	if err2 != nil {
		t.Error("Failed to download file after sharing with bob", err2)
		return
	}

	// check integrity of shared file
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is different than original")
		return
	}

	// append data to file
	newData := []byte("Yifan wants me to say that's cap")
	err = u1.AppendFile("file1", newData)

	// check if AppendFile worked
	if err != nil {
		t.Error("Failed to append to file1", err)
		return
	}

	// manually append data to check against function
	checkData := append(v1, newData...)

	v3, err := u1.LoadFile("file1")

	// check if file loads after appending
	if err != nil {
		t.Error("alice (owner) couldn't load file after append", err)
		return
	}

	// check if newData properly appended
	if !reflect.DeepEqual(checkData, v3) {
		t.Error("newData wasn't properly appended to the original file", string(checkData), string(v3))
		return
	}

	v4, err := u2.LoadFile("file2")
	// check if file loads for shared user after appending
	if err != nil {
		t.Error("File failed to load for Bob after append", err)
		return
	}

	// check file integrity for shared user after append
	if !(reflect.DeepEqual(v3, v4) && reflect.DeepEqual(v4, checkData)) {
		t.Error("Bob's version of the file was not the same as the original with the appended data")
		return
	}

}

// test file integrity after a shared user appends
func TestShareThenAppend(t *testing.T) {
	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// file
	v := []byte("wastemans")
	u1.StoreFile("file1", v)

	// test file loading
	_, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("alice's file didn't load", err)
		return
	}

	// share file
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test if file shared
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	// test if file received
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("bob didn't receive the share message", err)
		return
	}

	var v2 []byte
	v2, err2 = u2.LoadFile("file2")

	// check if file loads
	if err2 != nil {
		t.Error("Failed to download file after sharing with bob", err2)
		return
	}

	// check integrity of shared file
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is different than original")
		return
	}

	// append data to file (shared version)
	newData := []byte("that's Toronto slang")
	err = u2.AppendFile("file2", newData)

	// check if AppendFile worked
	if err != nil {
		t.Error("Failed to append to file2", err)
		return
	}

	// manually append data to check against function
	checkData := append(v, newData...)

	v3, err := u1.LoadFile("file1")
	// check if file loads for owner after shared user appends
	if err != nil {
		t.Error("alice (owner) couldn't load file after bob's append", err)
		return
	}

	// check if owner's version of file contains the correct data
	if !reflect.DeepEqual(checkData, v3) {
		t.Error("bob's newData wasn't properly appended to alice's file", string(checkData), string(v3))
		return
	}

	v4, err := u2.LoadFile("file2")
	// check if file loads for shared user after appending
	if err != nil {
		t.Error("File failed to load for bob after (bob's) append", err)
		return
	}

	// check file integrity for shared user after append
	if !reflect.DeepEqual(v4, checkData) {
		t.Error("bob and alice's version of files no longer same after bob's append")
		return
	}
}

// test shared user overwrite
func TestSharedUserOverwrite(t *testing.T) {
	clear()
	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	//  files
	v := []byte("I am sober enough to write this now")
	u1.StoreFile("file1", v)

	// load file
	v1, err := u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}

	// share file
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}

	// receive file
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive file", err)
		return
	}

	// more files
	v2 := []byte("lol only took me a nap to recover")
	// overwrite file2
	u2.StoreFile("file2", v2)

	// test load for alice
	v3, err := u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file for alice")
		return
	}

	// test content for alice
	if !reflect.DeepEqual(v2, v3) || reflect.DeepEqual(v1, v3) {
		t.Error("alice's loaded file doesn't have overwrite")
		return
	}

	// test content for bob
	v4, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file for bob", err)
		return
	}

	if !reflect.DeepEqual(v2, v4) || reflect.DeepEqual(v1, v4) {
		t.Error("bob's loaded file doesn't have overwrite")
		return
	}

}

// test magic_string integrity during share
func TestMagicString(t *testing.T) {
	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// file
	v := []byte("beep boop beep boop")
	u1.StoreFile("file1", v)

	// test file loading
	_, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("alice's file didn't load", err)
		return
	}

	// share file
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test if file shared
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	// tampered magic_string
	magic_string = string(userlib.RandomBytes(16))

	// test if file received
	err = u2.ReceiveFile("file1", "alice", magic_string)
	if err == nil {
		t.Error("magic string was tampered")
		return
	}

	var v2 []byte
	v2, err2 = u2.LoadFile("file1")

	// check if file loads
	if err2 == nil {
		t.Error("File should not have been shared since magic_string was tampered", err2)
		return
	}

	// check integrity of shared file
	if reflect.DeepEqual(v, v2) {
		t.Error("This shared file is the correct one, but it should not have been shared since magic_string was tampered")
		return
	}

}

// test sharing to non-existent user
func TestShareToFakeUser(t *testing.T) {
	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	var fakeUser User

	// test get user
	_, err = GetUser("fakeuser", "blah")
	if err == nil {
		t.Error("Got a user that doesn't exist")
		return
	}

	// file
	v := []byte("real homie")
	u1.StoreFile("file1", v)

	// test file loading
	_, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("alice's file didn't load", err)
		return
	}

	// share file wtih real user
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test if file shared
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	// test if file received
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("bob failed to receive alice's file", err)
		return
	}

	// owner shares with fake user
	var magic_string2 string
	magic_string2, err = u1.ShareFile("file1", "fakeuser")

	// test if file shared
	if err == nil {
		t.Error("Shared with a nonexistent user")
		return
	}

	// test if fake user received file
	err = fakeUser.ReceiveFile("file3", "alice", magic_string2)
	if err == nil {
		t.Error("Fake user should not have received this file")
		return
	}

	// test fake user creating new files
	v2 := []byte("fake homie")
	fakeUser.StoreFile("file4", v2)

	// load file for fake user
	_, err = fakeUser.LoadFile("file3")
	if err == nil {
		t.Error("This file was created by a fake user, should not have loaded")
		return
	}

	// test fake user share with real user

	_, err = fakeUser.ShareFile("file3", "bob")

	// test if fake user's file loads for real users
	_, err = u2.LoadFile("file3")
	if err == nil {
		t.Error("alice downloaded fake user's file")
		return
	}

}

// test sharing tree
func TestShareTree(t *testing.T) {
	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err3 := InitUser("carol", "christ")
	if err3 != nil {
		t.Error("Failed to initialize carol", err3)
		return
	}
	u4, err4 := InitUser("david", "beckham")
	if err4 != nil {
		t.Error("Failed to initialize david")
		return
	}

	// file
	v := []byte("senioritis is too real")
	u1.StoreFile("file1", v)

	// test file loading
	_, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("alice's file didn't load", err)
		return
	}

	// test unshared file access
	_, err = u2.LoadFile("file1")
	if err == nil {
		t.Error("bob should not have access to this file yet")
		return
	}

	// share file alice -> bob
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test if file shared
	if err != nil {
		t.Error("Failed to share the file with bob", err)
		return
	}

	// test if file loads for bob
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("bob didn't receive alice's file", err)
		return
	}

	// share file bob -> carol
	var magic_string2 string
	magic_string2, err = u2.ShareFile("file2", "carol")

	// test if file loads for carol
	err = u3.ReceiveFile("file3", "bob", magic_string2)
	if err != nil {
		t.Error("carol didn't receive bob's file", err)
		return
	}

	// revoke file access bob -> alice
	err = u2.RevokeFile("file2", "alice")
	if err == nil {
		t.Error("User can only revoke file access of other users they shared to")
		return
	}

	// revoke file access alice -> bob
	err = u1.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke child's file access", err)
		return
	}


	// test if bob can still share
	var magic_string3 string
	magic_string3, err = u2.ShareFile("file2", "david")
	if err == nil {
		t.Error("bob was able to share after access revoked")
		return
	}

	// test if david received the file from bob
	err = u4.ReceiveFile("file4", "bob", magic_string3)
	if err == nil {
		t.Error("david received bob's file after bob's access revoked")
		return
	}

	// test if david's file loads
	_, err = u4.LoadFile("file4")
	if err == nil {
		t.Error("david's file loaded even though it was shared from revoked user")
		return
	}

}

// test for filename uniqueness
func TestUniqueFileName(t *testing.T) {
	clear()
	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// alice's file
	v := []byte("OG file")
	u1.StoreFile("file1", v)

	// test file loading
	_, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("alice's file didn't load", err)
		return
	}

	// bob's file
	v2 := []byte("Overwrite?")
	u2.StoreFile("file1", v2)

	// test file loading
	_, err = u2.LoadFile("file1")
	if err != nil {
		t.Error("bob's file didn't load", err)
		return
	}

	// share file alice -> bob
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	if err != nil {
		t.Error("Failed to share alice's file with bob", err)
		return
	}

	// test receiving file (w/ same filename)
	err = u2.ReceiveFile("file1", "alice", magic_string)
	if err == nil {
		t.Error("file1 filename already exists for bob")
		return
	}

	// test receiving file (w/ different filename)
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("bob couldn't receive alice's file", err)
		return
	}
}

// test datastore entry compromise
func TestDatastoreWipe(t *testing.T) {
	clear()
	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// file
	v := []byte("As a member of the CS community...")
	u1.StoreFile("file1", v)

	// change Datastore
	userlib.DatastoreClear()

	// test file loading (shouldn't work)
	_, err = u1.LoadFile("file1")
	if err == nil {
		t.Error("Datastore entry was compromised, should not have loaded")
		return
	}

	// test sharing (shouldn't work)
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")
	if err == nil {
		t.Error("Datastore entry was compromised, should not have been able to share")
		return
	}

	// test receiving (shouldn't work)
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Datastore entry was compromised, should not have been able to receive file")
		return
	}

	// testing empty file
	v2 := []byte("")
	u2.StoreFile("file3", v2)

	// test load
	_, err = u2.LoadFile("file3")
	if err != nil {
		t.Error("failed to load file", err)
		return
	}

	// testing empty filename
	v3 := []byte("empty like my soul")
	u1.StoreFile("", v3)

	// test load
	_, err = u1.LoadFile("")
	if err != nil {
		t.Error("failed to load file", err)
		return
	}

}

// test compromised datastore
func TestCompromisedDatastore(t *testing.T) {

	clear()

	// users
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// files
	v := []byte("hallos")
	u1.StoreFile("file1", v)

	// test share
	var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test receive
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("failed to receive ", err)
		return
	}

	// test load
	v1, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("failed to load file", err)
		return
	}

	// datastore
	data := userlib.DatastoreGetMap()

	// compromise datastore
	for i, _ := range data {
		userlib.DatastoreSet(i, userlib.RandomBytes(16))
	}

	// test get user
	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("user info compromised, get should not have worked")
		return
	}

	_, err = GetUser("bob", "foobar")
	if err == nil {
		t.Error("user info compromised, get should not have worked")
		return
	}

	// test load (owner)
	v2, err := u1.LoadFile("file1")
	if err == nil {
		t.Error("file was corrupted, shouldn't have loaded")
		return
	}

	// test load (shared user)
	v3, err := u2.LoadFile("file2")
	if err == nil {
		t.Error("file was corrupted, shouldn't have loaded")
		return
	}

	// test file content
	if reflect.DeepEqual(v, v2) || reflect.DeepEqual(v1, v3) {
		t.Error("somehow the corruption didn't work ??? ")
		return
	}

	// test append
	newData := []byte("more data?")
	err = u2.AppendFile("file2", newData)
	if err == nil {
		t.Error("file was corrupted, shouldn't have been able to append")
		return
	}

	// test w diff number of bytes for corruption
	clear()

	// users
	u1, err = InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err2 = InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	// files
	v = []byte("hallos")
	u1.StoreFile("file1", v)

	// test share
	// var magic_string string
	magic_string, err = u1.ShareFile("file1", "bob")

	// test receive
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("failed to receive ", err)
		return
	}

	// test load
	v1, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("failed to load file", err)
		return
	}

	// datastore
	data = userlib.DatastoreGetMap()

	// compromise datastore
	for i, _ := range data {
		userlib.DatastoreSet(i, userlib.RandomBytes(1))
	}

	// test get user
	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("user info compromised, get should not have worked")
		return
	}
	_, err = GetUser("bob", "foobar")
	if err == nil {
		t.Error("user info compromised, get should not have worked")
		return
	}

	// test load (owner)
	v2, err = u1.LoadFile("file1")
	if err == nil {
		t.Error("file was corrupted, shouldn't have loaded")
		return
	}

	// test load (shared user)
	v3, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("file was corrupted, shouldn't have loaded")
		return
	}
	// test file content
	if reflect.DeepEqual(v, v2) || reflect.DeepEqual(v1, v3) {
		t.Error("somehow the corruption didn't work ??? ")
		return
	}

	// test append
	newData = []byte("more data?")
	err = u2.AppendFile("file2", newData)
	if err == nil {
		t.Error("file was corrupted, shouldn't have been able to append")
		return
	}

}
