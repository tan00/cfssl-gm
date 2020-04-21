package helpers

import (
	"bytes"
	"encoding/gob"
)

//DeepCopy 拷贝结构体中同名成员，传入参数均为有效指针
func DeepCopy(dst, src interface{}) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(src); err != nil {
		return err
	}
	return gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(dst)
}
