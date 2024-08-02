package stageController

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/orgNameToReplace/keymanager/server/db"
	pb "github.com/orgNameToReplace/proto/keymanager/golang"

	"github.com/golang/protobuf/proto"
	"github.com/rs/zerolog/log"
)

const (
	ControllerExpireTime = 1 * time.Minute
)

var (
	ErrKeyManagerInitErr = fmt.Errorf("keymanager init error")
)

var (
	logger = log.With().Caller().Str("module", "controller").Logger()
)

type IController interface {
	CanRemove() bool
	GetCurrentState(prefix string) string
	GetStage(ctx context.Context, req *pb.QueryStageRequest) *pb.QueryStageReply
	SubmitKey(ctx context.Context, req *pb.SubmitKeyRequest) *pb.SubmitKeyReply
	FetchData(ctx context.Context, req *pb.FetchDataRequest) (reply *pb.FetchDataReply, canRemove bool)
}

func NewController(ctx context.Context, command pb.Command, version int32) (IController, error) {
	if command != pb.Command_ONLINE_START_COMMAND {
		return nil, fmt.Errorf("not support command: %v", command)
	}

	// 查询当前版本是否在库里存在
	// 如果存在那么返回一个startController
	// 如果不存在那么返回一个initController
	cryptText, splitKeys, err := db.GetInfoByVersion(ctx, version)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get version info from db, err: %v", err.Error())
		return nil, fmt.Errorf("key manager init error")
	}
	if cryptText == nil || len(cryptText) == 0 ||
		splitKeys == nil || len(splitKeys) != 5 {
		return NewInitController(version)
	}

	return NewOnlineStartController(version)
}

func GetFailedRPCResult(msg string) *pb.CommonResult {
	return &pb.CommonResult{Code: pb.Code_FAILED, Msg: msg}
}

func GetSuccessRPCResult() *pb.CommonResult {
	return &pb.CommonResult{Code: pb.Code_SUCCESS}
}

func Verify(req proto.Message, signature []byte, pub ed25519.PublicKey) bool {
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return false
	}

	pubkey := pub
	return ed25519.Verify(pubkey, reqBytes, signature)
}

func GetSha256(info []byte) (data []byte) {
	data = make([]byte, 32)
	for i, b := range sha256.Sum256(info) {
		data[i] = b
	}

	return data
}
