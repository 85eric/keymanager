package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/orgNameToReplace/common/crypto"
	"github.com/orgNameToReplace/keymanager/server/config"
	"github.com/orgNameToReplace/keymanager/server/db"
	"github.com/orgNameToReplace/keymanager/server/stageController"
	"github.com/orgNameToReplace/keymanager/utils"
	pb "github.com/orgNameToReplace/proto/keymanager/golang"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

const (
	checkDataResult = "nightshade"
)

var (
	logger = log.With().Caller().Str("module", "server").Logger()

	_ pb.KeymanagerServer = &grpcServer{}

	GrpcServer = &grpcServer{}
)

// ===================================================================================================================

type grpcServer struct {
	pb.UnimplementedKeymanagerServer
	lock             sync.RWMutex
	accessLog        zerolog.Logger
	controllerMap    map[pb.Command]map[int32]stageController.IController
	pubkeyVersionMap map[int32]map[int]string // map[version]map[nodeIndex]base64(pubkey)
}

func Setup() {
	cfg, _ := config.GetConfig()

	err := db.InitDB(context.Background(), cfg)
	if err != nil {
		panic(err.Error())
	}
	http.HandleFunc("/internal/health", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/internal/debug", debug)

	http.HandleFunc("/internal/reset", resetIController)

	http.HandleFunc("/internal/confirm", confirmTempPubkey)

	fmt.Println("start listen internal interface at port ", cfg.Server.HttpAddr)
	go http.ListenAndServe(cfg.Server.HttpAddr, nil)

	// 输入启动密钥以启动程序
	initPassword()

	server := grpc.NewServer()
	GrpcServer = &grpcServer{
		accessLog:     log.With().Str("module", "rpc_caller").Logger(),
		controllerMap: map[pb.Command]map[int32]stageController.IController{},
	}

	pb.RegisterKeymanagerServer(server, GrpcServer)

	fmt.Println("start grpc server at port ", cfg.Server.GrpcAddr)
	listen, err := net.Listen("tcp", fmt.Sprintf("%v", cfg.Server.GrpcAddr))
	if err != nil {
		logger.Info().Msgf("error when listen port: %v, err: %v", cfg.Server.GrpcAddr, err.Error())
		panic(fmt.Sprintf("error when listen port: %v, err: %v", cfg.Server.GrpcAddr, err.Error()))
	}

	if err = server.Serve(listen); err != nil {
		panic(fmt.Sprintf("error when serve: %v, err: %v", cfg.Server.GrpcAddr, err.Error()))
	}
}

func initPassword() {
	pwdStr, err := crypto.GetPasswdPrompt("please input password: ", true, os.Stdin, os.Stdout)
	if err != nil {
		panic(fmt.Sprintf("error when get input password, err: %v", err.Error()))
	}

	pwd := crypto.GetDoubleHashByPwd(string(pwdStr))

	// 检查输入的密码是否正确
	checkData, err := db.GetClientEncryptKeyByVersion(context.Background(), -1)
	if err != nil {
		panic(fmt.Sprintf("error when get check km key data from db, err: %v", err.Error()))
	}

	result, err := crypto.DecryptWithCRC32(checkData, pwd)
	if err != nil {
		panic(fmt.Errorf("error when decrypt checkData by input pwd, err: %v", err.Error()))
	}

	if string(result) != checkDataResult {
		panic(fmt.Errorf("input pwd error, please check your input"))
	}

	config.SetEncryptKey(pwd)
}

func debug(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	GrpcServer.accessLog.Info().Ctx(ctx).Msgf("got debug request")
	defer GrpcServer.accessLog.Info().Ctx(ctx).Msgf("debug req end")

	GrpcServer.lock.RLock()
	defer GrpcServer.lock.RUnlock()

	w.Write([]byte(getJobDetails(GrpcServer.controllerMap)))
}

func resetIController(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()

	cmd := req.FormValue("cmd")
	versionStr := req.FormValue("v")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("version: %v not int, err: %v", versionStr, err.Error())))
		return
	}

	if (cmd != "start" && cmd != "init") ||
		version < 0 || version > math.MaxInt32 {
		logger.Info().Ctx(ctx).Msgf("param: cmd: %v, version: %v param not legal", cmd, version)
		w.Write([]byte(fmt.Sprintf("param error")))
		return
	}

	GrpcServer.accessLog.Info().Ctx(ctx).Msgf("got resetIController request, cmd: %v, v: %v", cmd, version)
	defer GrpcServer.accessLog.Info().Ctx(ctx).Msgf("resetIController end")

	GrpcServer.lock.RLock()
	defer GrpcServer.lock.RUnlock()

	realCmd := pb.Command_INIT_COMMAND
	switch cmd {
	case "start":
		realCmd = pb.Command_ONLINE_START_COMMAND
	case "init":
		realCmd = pb.Command_INIT_COMMAND
	}

	if jobMap, exist := GrpcServer.controllerMap[realCmd]; !exist {
		w.Write([]byte(fmt.Sprintf("target cmd: %v, realCmd: %v not exist\n", cmd, realCmd)))
	} else {
		if _, exist = jobMap[int32(version)]; !exist {
			w.Write([]byte(fmt.Sprintf("target version: %v not exist\n", version)))
		} else {
			delete(jobMap, int32(version))
			GrpcServer.controllerMap[realCmd] = jobMap
		}
	}

	w.Write([]byte("ok"))
}

func confirmTempPubkey(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()

	force := req.FormValue("force")
	versionStr := req.FormValue("v")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("version: %v not int, err: %v", versionStr, err.Error())))
		return
	}

	indexStr := req.FormValue("i")
	indexList := make([]int64, 0, len(strings.Split(indexStr, ",")))
	for _, str := range strings.Split(indexStr, ",") {
		index, err := strconv.ParseInt(str, 10, 64)
		if err != nil || index <= 0 || index >= 6 {
			w.Write([]byte(fmt.Sprintf("index: %v out of range(want 1-5), or err: %v", str, err)))
			return
		}

		indexList = append(indexList, index)
	}

	for _, index := range indexList {
		err = db.MoveTempPubKeyInfoToFileDB(ctx, index, int32(version), force == "t")
		if err != nil {
			w.Write([]byte(fmt.Sprintf("error when move index: %v, version: %v pubkey, err: %v\n", indexStr, version, err.Error())))
		}
	}

	w.Write([]byte("finish confirm"))
}

func getJobDetails(controllerMap map[pb.Command]map[int32]stageController.IController) string {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("current has %v cmd running\n", len(controllerMap)))

	for cmd, jobMap := range controllerMap {
		builder.WriteString(fmt.Sprintf("\tcmd: %v has %v version running\n", cmd, len(jobMap)))

		for version, ctrl := range jobMap {
			builder.WriteString(fmt.Sprintf("\t\tversion: %v:\n", version))
			builder.WriteString(fmt.Sprintf("\t\t\tcan remove: %v\n", ctrl.CanRemove()))
			builder.WriteString(fmt.Sprintf("\t\t\tcurrent state: \n%v", ctrl.GetCurrentState("\t\t\t\t")))
		}
	}

	return builder.String()
}

func (s *grpcServer) QueryStage(ctx context.Context, req *pb.QueryStageRequest) (reply *pb.QueryStageReply, err error) {
	ctx = utils.SetSpanId(ctx, utils.GetSpanId(ctx))
	reply = &pb.QueryStageReply{
		Result: &pb.CommonResult{
			Code: pb.Code_SUCCESS,
		},
	}

	s.accessLog.Info().Ctx(ctx).Msgf("receive QueryStage, req: %v", req.String())
	defer func() {
		msg := fmt.Sprintf("reply QueryStage, resp: %v, err: %v", reply.String(), err)
		if err != nil {
			msg = "[ALERT] " + msg
			err = nil
		}
		s.accessLog.Info().Ctx(ctx).Msgf("reply QueryStage, reply: %v", msg)
	}()

	c, err := s.GetOrInitStageController(ctx, req.Command, req.Version)
	if err != nil {
		reply.Result = stageController.GetFailedRPCResult(err.Error())
	} else {
		reply = c.GetStage(ctx, req)
	}

	return
}

func (s *grpcServer) SubmitMpcPublicKey(ctx context.Context, req *pb.SubmitMpcPublicKeyRequest) (reply *pb.SubmitMpcPublicKeyReply, err error) {
	ctx = utils.SetSpanId(ctx, utils.GetSpanId(ctx))
	reply = &pb.SubmitMpcPublicKeyReply{
		Result: &pb.CommonResult{
			Code: pb.Code_SUCCESS,
		},
	}

	s.accessLog.Info().Ctx(ctx).Msgf("receive SubmitMpcPublicKey, req: %v", req.String())
	defer func() {
		msg := fmt.Sprintf("reply SubmitMpcPublicKey, resp: %v, err: %v", reply.String(), err)
		if err != nil {
			msg = "[ALERT] " + msg
			err = nil
		}
		s.accessLog.Info().Ctx(ctx).Msgf("reply SubmitMpcPublicKey, reply: %v", msg)
	}()

	err = db.SaveTempPubKeyInfo(ctx, int64(req.NodeId), req.PublicKey, req.Version)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("node %v submit an exist pubkey: %v, version: %v, err: %v", req.NodeId, req.PublicKey, req.Version, err.Error())
		reply.Result.Code = pb.Code_FAILED
		reply.Result.Msg = "submit an exist pubkey"
	}

	return
}

func (s *grpcServer) QueryMpcPublicKey(ctx context.Context, req *pb.QueryMpcPublicKeyRequest) (reply *pb.QueryMpcPublicKeyReply, err error) {
	ctx = utils.SetSpanId(ctx, utils.GetSpanId(ctx))
	reply = &pb.QueryMpcPublicKeyReply{
		Result: &pb.CommonResult{
			Code: pb.Code_SUCCESS,
		},
	}

	s.accessLog.Info().Ctx(ctx).Msgf("receive QueryMpcPublicKey, req: %v", req.String())
	defer func() {
		msg := fmt.Sprintf("reply QueryMpcPublicKey, resp: %v, err: %v", reply.String(), err)
		if err != nil {
			msg = "[ALERT] " + msg
			err = nil
		}
		s.accessLog.Info().Ctx(ctx).Msgf("reply QueryMpcPublicKey, reply: %v", msg)
	}()

	allMpcPubKey := []db.PubkeyType{db.PubkeyMPC1, db.PubkeyMPC2, db.PubkeyMPC3, db.PubkeyMPC4, db.PubkeyMPC5}
	pubkeyList := make([]*pb.MpcPublicKeyInfo, 0, len(allMpcPubKey))
	for i := 0; i < len(allMpcPubKey); i++ {
		key, err := db.GetPubKey(ctx, req.Version, allMpcPubKey[i])
		if err != nil {
			logger.Error().Ctx(ctx).Msgf("error when get pubkey, err: %v", err.Error())
			continue
		}

		pubkeyList = append(pubkeyList, &pb.MpcPublicKeyInfo{
			NodeId:    int32(i + 1),
			PublicKey: base64.StdEncoding.EncodeToString(key),
		})
	}

	reply.PublicKeyList = pubkeyList
	return
}

func (s *grpcServer) SubmitKey(ctx context.Context, req *pb.SubmitKeyRequest) (reply *pb.SubmitKeyReply, err error) {
	ctx = utils.SetSpanId(ctx, utils.GetSpanId(ctx))
	reply = &pb.SubmitKeyReply{
		Result: &pb.CommonResult{
			Code: pb.Code_SUCCESS,
		},
	}

	s.accessLog.Info().Ctx(ctx).Msgf("receive SubmitKey, req: %v", req.String())
	defer func() {
		msg := fmt.Sprintf("reply SubmitKey, resp: %v, err: %v", reply.String(), err)
		if err != nil {
			msg = "[ALERT] " + msg
			err = nil
		}
		s.accessLog.Info().Ctx(ctx).Msgf("reply SubmitKey, reply: %v", msg)
	}()

	c, err := s.GetOrInitStageController(ctx, req.Command, req.Version)
	if err != nil {
		reply.Result = stageController.GetFailedRPCResult(err.Error())
	} else {
		reply = c.SubmitKey(ctx, req)
	}
	return
}

func (s *grpcServer) FetchData(ctx context.Context, req *pb.FetchDataRequest) (reply *pb.FetchDataReply, err error) {
	ctx = utils.SetSpanId(ctx, utils.GetSpanId(ctx))
	reply = &pb.FetchDataReply{
		Result: &pb.CommonResult{
			Code: pb.Code_SUCCESS,
		},
	}

	s.accessLog.Info().Ctx(ctx).Msgf("receive FetchData, req: %v", req.String())
	defer func() {
		msg := fmt.Sprintf("reply FetchData, resp: %v, err: %v", reply.String(), err)
		if err != nil {
			msg = "[ALERT] " + msg
			err = nil
		}
		s.accessLog.Info().Ctx(ctx).Msgf("reply FetchData, reply: %v", msg)
	}()

	var canRemove bool
	c, err := s.GetOrInitStageController(ctx, req.Command, req.Version)
	if err != nil {
		reply.Result = stageController.GetFailedRPCResult(err.Error())
	} else {
		reply, canRemove = c.FetchData(ctx, req)
	}

	if canRemove {
		s.RemoveStageController(req.Command, req.Version)
	}

	return
}

func (s *grpcServer) GetOrInitStageController(ctx context.Context, command pb.Command, version int32) (stageController.IController, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, exist := s.controllerMap[command]; !exist {
		s.controllerMap[command] = make(map[int32]stageController.IController)
	}

	versionMap := s.controllerMap[command]
	if _, exist := versionMap[version]; !exist {
		controller, err := stageController.NewController(ctx, command, version)
		if err != nil {
			return nil, err
		}
		versionMap[version] = controller
	}

	controller := versionMap[version]
	return controller, nil
}

func (s *grpcServer) RemoveStageController(command pb.Command, version int32) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, exist := s.controllerMap[command]; !exist {
		return
	}

	versionMap := s.controllerMap[command]
	if _, exist := versionMap[version]; !exist {
		return
	}

	delete(versionMap, version)
}
