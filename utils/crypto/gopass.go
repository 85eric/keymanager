/*
 * *******************************************************************
 * @项目名称: common
 * @文件名称: gopass.go
 * @Date: 2018/08/02
 * @Author: chunhua.guo
 * @Copyright（C）: 2018 BlueHelix Inc.   All rights reserved.
 * 注意：本内容仅限于内部传阅，禁止外泄以及用于其他的商业目的.
 * *******************************************************************
 */

package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

const hexKeyLen = 64

// ReadPasswd read secret key from terminal
func ReadPasswd(prom string) (string, error) {
	passwd1, err := GetPasswdPrompt(prom, true, os.Stdin, os.Stdout)
	if err != nil {
		return "", fmt.Errorf("length of password should be 64, input password error %v", err)
	}
	passwd2, err := GetPasswdPrompt("please input again:", true, os.Stdin, os.Stdout)
	if err != nil {
		return "", fmt.Errorf("input password error")
	}

	if bytes.Compare(passwd1, passwd2) != 0 {
		return "", fmt.Errorf("password not matched")
	}
	return string(passwd1), nil
}

// the following code come from https://github.com/howeyc/gopass
type terminalState struct {
	state *terminal.State
}

func isTerminal(fd uintptr) bool {
	return terminal.IsTerminal(int(fd))
}

func makeRaw(fd uintptr) (*terminalState, error) {
	state, err := terminal.MakeRaw(int(fd))

	return &terminalState{
		state: state,
	}, err
}

func restore(fd uintptr, oldState *terminalState) error {
	return terminal.Restore(int(fd), oldState.state)
}

type FdReader interface {
	io.Reader
	Fd() uintptr
}

var defaultGetCh = func(r io.Reader) (byte, error) {
	buf := make([]byte, 1)
	if n, err := r.Read(buf); n == 0 || err != nil {
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	return buf[0], nil
}

var (
	maxLength            = 512
	ErrInterrupted       = fmt.Errorf("interrupted")
	ErrMaxLengthExceeded = fmt.Errorf("maximum byte limit (%v) exceeded", maxLength)

	// Provide variable so that tests can provide a mock implementation.
	getch = defaultGetCh
)

// InputType input type enum
type InputType uint32

const (
	// Invisible 输入字符不可见
	Invisible InputType = iota
	// Mask *显示
	Masked
	// Visible 明文显示
	Visible
)

// getString returns the input read from terminal.
// If prompt is not empty, it will be output as a prompt to the user
// If InputType is Invisible, typing will echo nothing.
// If InputType is Masked, typing will be matched by asterisks on the screen.
// Otherwise, typing will echo the origin content.
func getString(prompt string, input InputType, r FdReader, w io.Writer) ([]byte, error) {
	var err error
	var pass, bs, mask []byte

	if input == Masked {
		mask = []byte("*")
	}

	if input != Invisible {
		bs = []byte("\b \b")
	}

	if isTerminal(r.Fd()) {
		if oldState, err := makeRaw(r.Fd()); err != nil {
			return pass, err
		} else {
			defer func() {
				restore(r.Fd(), oldState)
				fmt.Fprintln(w)
			}()
		}
	}

	if prompt != "" {
		fmt.Fprint(w, prompt)
	}

	// Track total bytes read, not just bytes in the password.  This ensures any
	// errors that might flood the console with nil or -1 bytes infinitely are
	// capped.
	var counter int
	for counter = 0; counter <= maxLength; counter++ {
		if v, e := getch(r); e != nil {
			err = e
			break
		} else if v == 127 || v == 8 {
			if l := len(pass); l > 0 {
				pass = pass[:l-1]
				fmt.Fprint(w, string(bs))
			}
		} else if v == 13 || v == 10 {
			break
		} else if v == 3 {
			err = ErrInterrupted
			break
		} else if v != 0 {
			pass = append(pass, v)
			if input != Visible {
				fmt.Fprint(w, string(mask))
			} else {
				fmt.Fprint(w, string(v))
			}
		}
	}

	if counter > maxLength {
		err = ErrMaxLengthExceeded
	}

	return pass, err
}

// getPasswd returns the input read from terminal.
// If prompt is not empty, it will be output as a prompt to the user
// If masked is true, typing will be matched by asterisks on the screen.
// Otherwise, typing will echo nothing.
func getPasswd(prompt string, masked bool, r FdReader, w io.Writer) ([]byte, error) {
	var input InputType
	if masked {
		input = Masked
	} else {
		input = Invisible
	}
	return getString(prompt, input, r, w)
}

// GetPasswd returns the password read from the terminal without echoing input.
// The returned byte array does not include end-of-line characters.
func GetPasswd() ([]byte, error) {
	return getPasswd("", false, os.Stdin, os.Stdout)
}

// GetPasswdMasked returns the password read from the terminal, echoing asterisks.
// The returned byte array does not include end-of-line characters.
func GetPasswdMasked() ([]byte, error) {
	return getPasswd("", true, os.Stdin, os.Stdout)
}

// GetPasswdPrompt prompts the user and returns the password read from the terminal.
// If mask is true, then asterisks are echoed.
// The returned byte array does not include end-of-line characters.
func GetPasswdPrompt(prompt string, mask bool, r FdReader, w io.Writer) ([]byte, error) {
	return getPasswd(prompt, mask, r, w)
}

// GetStringPrompt prompts the user and returns the password read from the terminal.
// The returned byte array does not include end-of-line characters.
func GetStringPrompt(prompt string, r FdReader, w io.Writer) ([]byte, error) {
	input := Visible
	return getString(prompt, input, r, w)
}
