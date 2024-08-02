package stageController

import (
	"context"
	"time"

	pb "github.com/orgNameToReplace/proto/keymanager/golang"
)

type UnImplController struct {
	updateAt time.Time
	msg      string
}

func NewUnImplController(msg string) IController {
	return &UnImplController{
		updateAt: time.Now(),
		msg:      msg,
	}
}

func (u *UnImplController) CanRemove() bool {
	return time.Now().After(u.updateAt.Add(ControllerExpireTime))
}

func (u *UnImplController) GetCurrentState(prefix string) string {
	return u.msg
}

func (u *UnImplController) GetStage(ctx context.Context, req *pb.QueryStageRequest) *pb.QueryStageReply {
	return &pb.QueryStageReply{
		Result: GetFailedRPCResult(u.msg),
	}
}

func (u *UnImplController) SubmitKey(ctx context.Context, req *pb.SubmitKeyRequest) *pb.SubmitKeyReply {
	return &pb.SubmitKeyReply{
		Result: GetFailedRPCResult(u.msg),
	}
}

func (u *UnImplController) FetchData(ctx context.Context, req *pb.FetchDataRequest) (reply *pb.FetchDataReply, canRemove bool) {
	return &pb.FetchDataReply{
		Result: GetFailedRPCResult(u.msg),
	}, false
}
