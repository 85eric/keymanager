package stageController

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/orgNameToReplace/common/crypto"
	"github.com/orgNameToReplace/common/models"
	"github.com/orgNameToReplace/keymanager/common"
	"github.com/orgNameToReplace/keymanager/server/config"
	"github.com/orgNameToReplace/keymanager/server/db"
	"github.com/orgNameToReplace/keymanager/utils"
	pb "github.com/orgNameToReplace/proto/keymanager/golang"
)

type InitController struct {
	version          int32
	clientEncryptKey []byte
	inputPwdSuffix   []byte

	timeLock sync.RWMutex
	updateAt time.Time

	stageLock    sync.RWMutex
	currentStage pb.Stage

	sendKeyLock sync.Mutex
	trueKeys    [][]byte // keymanager 加密 mpc 节点密钥

	onlineLayer1EncryptKey       []byte   // 第一层加密密钥   对应 2-1
	onlineLayer2EncryptKey       []byte   // 第二层加密密钥   对应 5-3
	onlineLayer2SplitKeys        [][]byte // 第二层加密密钥的分片
	onlineLayer1AfterEncryptData []byte   // 使用第一层加密密钥加密 trueKeys 后的数据

	inputKeyLock                      sync.Mutex
	onlineLayer2AfterEncryptData      []byte   // 使用 2_1 输入密钥加密 layer1AfterEncryptData 和 layer1EncryptKey 后的数据
	onlineLayer2AfterInputEncryptData [][]byte // 使用 5_3 输入密钥加密 layer2SplitKeys 后的数据
}

func NewInitController(version int32) (IController, error) {
	ctx := utils.SetSpanId(context.Background())

	layer2CryptText, encryptedSplitKeys, err := db.GetInfoByVersion(ctx, version)
	hasKey := false
	for _, key := range encryptedSplitKeys {
		if key != nil && len(key) > 0 {
			hasKey = true
			break
		}
	}
	if err == nil && (len(layer2CryptText) > 0 || hasKey) {
		logger.Error().Ctx(ctx).Msgf("version: %v already exist", version)
		return nil, fmt.Errorf("can't new init controller, version %v exist", version)
	}

	conf, err := config.GetConfig()
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get config, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}

	encryptKey, err := db.GetClientEncryptKeyByVersion(ctx, version)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get client encryptKey from db, version: %v, err: %v", version, err.Error())
		return nil, ErrKeyManagerInitErr
	}
	if len(encryptKey) == 0 {
		logger.Error().Ctx(ctx).Msgf("version: %v client encrypt key is empty, please check!!!")
		return nil, ErrKeyManagerInitErr
	}
	encryptKey, err = crypto.DecryptWithCRC32(encryptKey, conf.EncryptKey)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when decrypt client encrypt key, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}
	encryptKey = crypto.GetDoubleHashByPwd(string(encryptKey))

	c := &InitController{
		version:                           version,
		clientEncryptKey:                  encryptKey,
		inputPwdSuffix:                    append([]byte("-----"), encryptKey...),
		updateAt:                          time.Now(),
		currentStage:                      pb.Stage_WAIT_ONLINE_2_1,
		onlineLayer2AfterInputEncryptData: make([][]byte, 5),
	}

	c.trueKeys,
		c.onlineLayer1EncryptKey, c.onlineLayer2EncryptKey, c.onlineLayer2SplitKeys,
		err = GenerateAllNeedKeys(ctx)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when generateAllNeedKeys, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}

	encodedTrueKeys, err := utils.GobEncode(append(c.trueKeys, common.KeyManagerDefaultSuffix))
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when encode true keys, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}

	c.onlineLayer1AfterEncryptData, err = crypto.EncryptWithCRC32(encodedTrueKeys, c.onlineLayer1EncryptKey)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when encode true keys, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}

	c.onlineLayer2SplitKeys, err = MixSplit53Keys(c.onlineLayer2SplitKeys)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when mix split key, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}

	return c, nil
}

// CanRemove 是否可以移除
func (i *InitController) CanRemove() bool {
	i.timeLock.RLock()
	defer i.timeLock.RUnlock()

	if i.getStage(pb.ClientType_ONLINE_CLIENT_5_3) == pb.Stage_ONLINE_FINISH {
		return true
	}

	return i.updateAt.After(time.Now().Add(ControllerExpireTime))
}

// GetCurrentState 返回当前controller状态
func (i *InitController) GetCurrentState(prefix string) string {
	builder := strings.Builder{}

	i.timeLock.RLock()
	builder.WriteString(fmt.Sprintf("%vlastupdate at: %v\n", prefix, i.updateAt.Format(time.RFC3339)))
	i.timeLock.RUnlock()

	i.stageLock.RLock()
	builder.WriteString(fmt.Sprintf("%vcurrent online stage: %v\n", prefix, i.currentStage))
	i.stageLock.RUnlock()

	i.inputKeyLock.Lock()
	builder.WriteString(fmt.Sprintf("%vonline 2-1 is input: %v\n",
		prefix, i.onlineLayer2AfterEncryptData != nil && len(i.onlineLayer2AfterEncryptData) >= 0))
	for index, data := range i.onlineLayer2AfterInputEncryptData {
		builder.WriteString(fmt.Sprintf("%vonline 5-3 index: %v, is input: %v\n",
			prefix, index+1, data != nil && len(data) >= 0))
	}
	i.inputKeyLock.Unlock()

	i.sendKeyLock.Lock()
	for index, data := range i.trueKeys {
		builder.WriteString(fmt.Sprintf("%vmpc_%v node has fetch data: %v\n",
			prefix, index, i.currentStage == pb.Stage_WAIT_FETCH_DATA_MPC && (data == nil || len(data) == 0)))
	}
	i.sendKeyLock.Unlock()

	builder.WriteString("\n")
	return builder.String()
}

// GetStage 获取当前stage 以及是否需要当前请求客户端输入等信息
func (i *InitController) GetStage(ctx context.Context, req *pb.QueryStageRequest) (reply *pb.QueryStageReply) {
	stage := i.getStage(req.ClientType)
	if i.hasInput() {
		i.refreshTime()
	}

	needInput := false

	i.inputKeyLock.Lock()
	if i.currentStage == pb.Stage_WAIT_ONLINE_2_1 && req.ClientType == pb.ClientType_ONLINE_CLIENT_2_1 {
		// 如果是2-1 并且正在等待 2-1 输入, 那么需要输入
		if i.onlineLayer2AfterEncryptData == nil || len(i.onlineLayer2AfterEncryptData) == 0 {
			needInput = true
		}
	} else if i.currentStage == pb.Stage_WAIT_ONLINE_5_3 && req.ClientType == pb.ClientType_ONLINE_CLIENT_5_3 {
		// 如果是5-3 并且正在等待 5-3 输入, 那么判断当前index是否需要输入
		if i.onlineLayer2AfterInputEncryptData[req.ClientIndex-1] == nil || len(i.onlineLayer2AfterInputEncryptData[req.ClientIndex-1]) == 0 {
			needInput = true
		}
	}
	i.inputKeyLock.Unlock()

	jobFinish := false
	switch req.ClientType {
	case pb.ClientType_CLIENT_MPC:
		if stage == pb.Stage_ONLINE_FINISH {
			jobFinish = true
		}
	case pb.ClientType_ONLINE_CLIENT_5_3:
		if stage == pb.Stage_WAIT_FETCH_DATA_MPC || stage == pb.Stage_ONLINE_FINISH {
			jobFinish = true
		}
	case pb.ClientType_ONLINE_CLIENT_2_1:
		if stage == pb.Stage_WAIT_OFFLINE_5_3 || stage == pb.Stage_WAIT_FETCH_DATA_MPC || stage == pb.Stage_ONLINE_FINISH {
			jobFinish = true
		}
	}

	return &pb.QueryStageReply{
		Result:          GetSuccessRPCResult(),
		Stage:           stage,
		NeedInput:       needInput,
		NeedDoubleCheck: needInput, // 因为是初始化, 所以都需要输入两次密码
		JobFinish:       jobFinish,
	}
}

func (i *InitController) SubmitKey(ctx context.Context, req *pb.SubmitKeyRequest) *pb.SubmitKeyReply {
	// 是否合法的 clientType
	if req.ClientType != pb.ClientType_ONLINE_CLIENT_5_3 && req.ClientType != pb.ClientType_ONLINE_CLIENT_2_1 {
		logger.Info().Ctx(ctx).Msgf("wrong client type, got: %v", req.ClientType)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("you don't need input")}
	}

	if (req.ClientType == pb.ClientType_ONLINE_CLIENT_5_3) &&
		(req.ClientIndex < 1 || req.ClientIndex > 5) {
		logger.Info().Ctx(ctx).Msgf("wrong client index, got: %v", req.ClientIndex)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("you don't need input")}
	}

	// 先判断是否为当前阶段
	if i.getStage(req.ClientType) != req.Stage {
		logger.Info().Ctx(ctx).Msgf("wrong stage, current: %v, got: %v", i.getStage(req.ClientType), req.Stage)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("not your stage to input")}
	}

	// 只有是当前阶段的人才该输入，其它不应该输入
	if !(req.Stage == pb.Stage_WAIT_ONLINE_2_1 && req.ClientType == pb.ClientType_ONLINE_CLIENT_2_1 ||
		req.Stage == pb.Stage_WAIT_ONLINE_5_3 && req.ClientType == pb.ClientType_ONLINE_CLIENT_5_3) {
		logger.Info().Ctx(ctx).Msgf("wrong stage, current: %v, got: %v", i.getStage(req.ClientType), req.Stage)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("not your stage to input")}
	}

	// 储存密码
	err := i.inputPassword(ctx, req.ClientType, req.ClientIndex, req.KeyData)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when inputPassword, err: %v", err.Error())
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult(err.Error())}
	}

	if i.getStage(req.ClientType) == pb.Stage_WAIT_FETCH_DATA_MPC {
		// 在线流程完了，可以把数据写到数据库了
		// 使用 5_3 加密的 分片密钥 信息
		for index, data := range i.onlineLayer2AfterInputEncryptData {
			err = db.SaveKeyInfo(ctx, models.MPCNodeKeyTypeSplitSecret, int64(index), data, i.version)
			if err != nil {
				logger.Info().Ctx(ctx).Msgf("error when save encrypted data, err: %v", err.Error())
				return &pb.SubmitKeyReply{Result: GetFailedRPCResult("key manager error")}
			}
		}

		// 使用 分片密钥 加密的信息
		err = db.SaveKeyInfo(ctx, models.MPCNodeKeyTypeCryptText, 0, i.onlineLayer2AfterEncryptData, i.version)
		if err != nil {
			logger.Info().Ctx(ctx).Msgf("error when save encrypted data, err: %v", err.Error())
			return &pb.SubmitKeyReply{Result: GetFailedRPCResult("key manager error")}
		}
	}

	return &pb.SubmitKeyReply{Result: GetSuccessRPCResult()}
}

func (i *InitController) FetchData(ctx context.Context, req *pb.FetchDataRequest) (reply *pb.FetchDataReply, canRemove bool) {
	// 是否合法的 clientType
	if req.ClientType != pb.ClientType_CLIENT_MPC {
		return &pb.FetchDataReply{Result: GetFailedRPCResult("you can't fetch data")}, false
	}

	// 判断是否为当前阶段
	stage := i.getStage(req.ClientType)
	if stage != req.Stage {
		return &pb.FetchDataReply{Result: GetFailedRPCResult("not your stage to fetch data")}, false
	}

	// 判断签名
	if !i.checkSign(ctx, req) {
		return &pb.FetchDataReply{Result: GetFailedRPCResult("you can't fetch data")}, false
	}

	// 给出数据
	var data []byte
	var err error
	switch req.ClientType {
	case pb.ClientType_CLIENT_MPC:
		i.sendKeyLock.Lock()
		data, err = i.getMPCKey(ctx, req.ClientIndex)
		i.sendKeyLock.Unlock()

		// 里边会做判断
		i.nextStage(true)
	default:
		return &pb.FetchDataReply{Result: GetFailedRPCResult("you can't fetch data")}, false
	}
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when fetch data, err: %v", err.Error())
		return &pb.FetchDataReply{Result: GetFailedRPCResult("error when fetch data")}, false
	}

	canRemove = i.getStage(pb.ClientType_ONLINE_CLIENT_5_3) == pb.Stage_ONLINE_FINISH

	return &pb.FetchDataReply{
		Result: GetSuccessRPCResult(),
		Data:   data,
	}, canRemove
}

func (i *InitController) refreshTime() {
	i.timeLock.Lock()
	defer i.timeLock.Unlock()
	i.updateAt = time.Now()
}

func (i *InitController) getStage(clientType pb.ClientType) pb.Stage {
	i.stageLock.RLock()
	defer i.stageLock.RUnlock()

	switch clientType {
	case pb.ClientType_ONLINE_CLIENT_5_3, pb.ClientType_ONLINE_CLIENT_2_1, pb.ClientType_CLIENT_MPC:
		return i.currentStage
	default:
		return pb.Stage_UNKNOWN_STAGE
	}
}

func (i *InitController) nextStage(updateOnlineStage bool) {
	i.stageLock.Lock()
	defer i.stageLock.Unlock()
	i.refreshTime()

	if updateOnlineStage {
		switch i.currentStage {
		case pb.Stage_WAIT_ONLINE_2_1:
			i.currentStage = pb.Stage_WAIT_ONLINE_5_3
		case pb.Stage_WAIT_ONLINE_5_3:
			i.currentStage = pb.Stage_WAIT_FETCH_DATA_MPC
		case pb.Stage_WAIT_FETCH_DATA_MPC:
			i.sendKeyLock.Lock()
			if len(i.trueKeys) == 0 {
				i.currentStage = pb.Stage_ONLINE_FINISH
			}
			allFetched := true
			for _, data := range i.trueKeys {
				if data != nil || len(data) > 0 {
					allFetched = false
				}
			}
			if allFetched {
				i.currentStage = pb.Stage_ONLINE_FINISH
			}
			i.sendKeyLock.Unlock()
		case pb.Stage_ONLINE_FINISH:
			i.currentStage = pb.Stage_ONLINE_FINISH
		}
	}
}

func (i *InitController) hasInput() bool {
	i.inputKeyLock.Lock()
	defer i.inputKeyLock.Unlock()

	if len(i.onlineLayer2AfterEncryptData) > 0 {
		return true
	}

	for _, info := range i.onlineLayer2AfterInputEncryptData {
		if info != nil && len(info) > 0 {
			return true
		}
	}

	return false
}

func (i *InitController) inputPassword(ctx context.Context, clientType pb.ClientType, index int32, inputPwd []byte) error {
	i.inputKeyLock.Lock()
	defer i.inputKeyLock.Unlock()

	var err error
	inputPwd, err = crypto.DecryptWithCRC32(inputPwd, i.clientEncryptKey)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf(" error when decrypt client key, err: %v", err.Error())
		return fmt.Errorf("client version mismatch, please update client binary")
	}
	if !bytes.HasSuffix(inputPwd, i.inputPwdSuffix) {
		logger.Info().Ctx(ctx).Msgf("client type: %v, index: %v not use target communicate key, need check",
			clientType, index)
		return fmt.Errorf("client communicate key error, please recheck communicate key")
	} else {
		inputPwd = bytes.TrimSuffix(inputPwd, i.inputPwdSuffix)
	}

	inputPwd = crypto.GetDoubleHashByPwd(string(inputPwd))

	switch clientType {
	case pb.ClientType_ONLINE_CLIENT_2_1:
		// 判断是否已经输入密码
		if i.onlineLayer2AfterEncryptData != nil && len(i.onlineLayer2AfterEncryptData) > 0 {
			return fmt.Errorf("you have already input password")
		}

		info, err := i.do21Encrypt(ctx, i.onlineLayer1EncryptKey, i.onlineLayer1AfterEncryptData, inputPwd, true)
		if err != nil {
			return err
		}
		i.onlineLayer2AfterEncryptData = info
		i.nextStage(true)

	case pb.ClientType_ONLINE_CLIENT_5_3:
		// 判断是否已经输入密码
		if i.onlineLayer2AfterInputEncryptData[index-1] != nil && len(i.onlineLayer2AfterInputEncryptData[index-1]) > 0 {
			return fmt.Errorf("you have already input password")
		}
		info, err := i.do53Encrypt(ctx, i.onlineLayer2SplitKeys[index-1], inputPwd)
		if err != nil {
			return err
		}
		i.onlineLayer2AfterInputEncryptData[index-1] = info

		// 如果全部输入完成，可以进入下一步
		allUpdate := true
		for _, encryptData := range i.onlineLayer2AfterInputEncryptData {
			if encryptData == nil || len(encryptData) == 0 {
				allUpdate = false
				break
			}
		}
		if allUpdate {
			i.nextStage(true)
		}

	default:
		return fmt.Errorf("you don't need input")
	}

	return nil
}

func (i *InitController) do21Encrypt(ctx context.Context, encryptKey, encryptData, key []byte, isOnline bool) (data []byte, err error) {
	keyAfterEncrypt, err := crypto.EncryptWithCRC32(append(encryptKey, common.KeyManagerDefaultSuffix...), key)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when encrypt, err: %v", err.Error())
		return nil, fmt.Errorf("key manager error")
	}

	data, err =
		utils.GobEncode([][]byte{encryptData, keyAfterEncrypt, common.KeyManagerDefaultSuffix})
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when gob.encode, err: %v", err.Error())
		return nil, fmt.Errorf("ey manager error")
	}

	if isOnline {
		data, err = crypto.EncryptWithCRC32(data, i.onlineLayer2EncryptKey)
	}
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when encrypt, err: %v", err.Error())
		return nil, fmt.Errorf("key manager error")
	}

	return data, nil
}

func (i *InitController) do53Encrypt(ctx context.Context, data, key []byte) (result []byte, err error) {
	result, err = crypto.EncryptWithCRC32(data, key)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when encrypt, err: %v", err.Error())
		return nil, fmt.Errorf("key manager error")
	}

	return result, nil
}

func (i *InitController) checkSign(ctx context.Context, req *pb.FetchDataRequest) bool {
	var keyType db.PubkeyType
	switch req.ClientType {
	case pb.ClientType_CLIENT_MPC:
		switch req.ClientIndex {
		case 1:
			keyType = db.PubkeyMPC1
		case 2:
			keyType = db.PubkeyMPC2
		case 3:
			keyType = db.PubkeyMPC3
		case 4:
			keyType = db.PubkeyMPC4
		case 5:
			keyType = db.PubkeyMPC5
		default:
			return false
		}
	default:
		return false
	}

	var pubKey ed25519.PublicKey
	var err error
	pubKey, err = db.GetPubKey(ctx, req.Version, keyType)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when get pubkey of clientType: %v, keyType: %v, err: %v", req.ClientType, keyType, err.Error())
		return false
	}

	// checkSign
	signData, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when decode sign, sign: %v, err: %v", req.Signature, err.Error())
		return false
	}

	return Verify(&pb.FetchDataRequest{
		Command:     req.Command,
		Stage:       req.Stage,
		ClientType:  req.ClientType,
		ClientIndex: req.ClientIndex,
		Version:     req.Version,
		Nonce:       req.Nonce,
		Timestamp:   req.Timestamp,
	}, signData, pubKey)
}

func (i *InitController) getMPCKey(ctx context.Context, index int32) (data []byte, err error) {
	if index < 1 || index > 5 {
		logger.Info().Ctx(ctx).Msgf("wrong index, want 1-5 got: %v", index)
		return nil, fmt.Errorf("can't fetch data")
	}

	if i.trueKeys == nil || len(i.trueKeys) == 0 {
		logger.Info().Ctx(ctx).Msgf("node key is empty")
		return nil, fmt.Errorf("can't fetch data")
	}

	trueKey := i.trueKeys[index-1]
	if len(trueKey) == 0 {
		logger.Info().Ctx(ctx).Msgf("empty node key or empty true key")
		return nil, fmt.Errorf("can't fetch data")
	}

	info := common.SyncMPCNodeNeedMsg{
		TrueKey: trueKey,
	}

	i.trueKeys[index-1] = nil

	data, err = utils.GobEncode(info)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when gob encode, err: %v", err.Error())
		return nil, fmt.Errorf("can't fetch data")
	}

	return data, nil
}

func GenerateAllNeedKeys(ctx context.Context) (
	trueKeys [][]byte,
	onlineLayer1EncryptKey []byte, onlineLayer2EncryptKey []byte, onlineLayer3SplitKeys [][]byte,
	err error) {

	trueKeys = make([][]byte, 5)

	onlineLayer1EncryptKey = make([]byte, 0)
	onlineLayer2EncryptKey = make([]byte, 0)
	onlineLayer3SplitKeys = make([][]byte, 10)

	// generate true keys
	for i, trueKey := range trueKeys {
		trueKey, err = crypto.InitRandomKey(common.DefaultSecretLength)
		if err != nil {
			logger.Error().Ctx(ctx).Msgf("error when get trueKeys, err: %v", err.Error())
			return
		}

		trueKeys[i] = trueKey
	}

	// onlineLayer1EncryptKey
	onlineLayer1EncryptKey, err = crypto.InitRandomKey(common.DefaultSecretLength)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get onlineLayer1EncryptKey, err: %v", err.Error())
		return
	}

	// onlineLayer2EncryptKey + onlineLayer3SplitKeys
	h := sha256.New()
	for i, key := range onlineLayer3SplitKeys {
		key, err = crypto.InitRandomKey(common.DefaultSecretLength)
		if err != nil {
			logger.Error().Ctx(ctx).Msgf("error when get onlineLayer3SplitKeys, err: %v", err.Error())
			return
		}
		_, err = h.Write(key)
		if err != nil {
			logger.Error().Ctx(ctx).Msgf("error when generate onlineLayer2EncryptKey, err: %v", err.Error())
			return
		}

		onlineLayer3SplitKeys[i] = key
	}
	onlineLayer2EncryptKey = h.Sum(nil)

	return
}

func MixSplit53Keys(splitKeys [][]byte) ([][]byte, error) {
	if len(splitKeys) != 10 {
		return nil, fmt.Errorf("splitKey length is not 10")
	}
	result := make([][]byte, 5)

	for i, plainText := range result {
		var err error
		plainTextSlice := make([][]byte, 7)

		for j, index := range common.SplitKeysIndex[i] {
			plainTextSlice[j] = splitKeys[index]
		}

		plainTextSlice[6] = common.KeyManagerDefaultSuffix

		plainText, err = utils.GobEncode(plainTextSlice)
		if err != nil {
			return nil, err
		}

		result[i] = plainText
	}

	return result, nil
}
