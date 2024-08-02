package stageController

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/orgNameToReplace/common/crypto"
	"github.com/orgNameToReplace/keymanager/common"
	"github.com/orgNameToReplace/keymanager/server/config"
	"github.com/orgNameToReplace/keymanager/server/db"
	"github.com/orgNameToReplace/keymanager/utils"
	pb "github.com/orgNameToReplace/proto/keymanager/golang"
)

type OnlineStartController struct {
	timeLock sync.RWMutex
	updateAt time.Time

	version          int32
	clientEncryptKey []byte
	inputPwdSuffix   []byte

	stageLock    sync.RWMutex
	currentStage pb.Stage

	sendKeyLock sync.Mutex
	trueKeys    [][]byte // keymanager 加密 mpc 节点密钥

	inputKeyLock      sync.Mutex
	layer1HasInput    bool     // 2_1 是否已经输入密码
	layer2CryptText   []byte   // 第二层加密后的密文 (使用 decryptedSplitKeys 组合成 第二层加密密钥后解密)
	layer2DecryptText [][]byte // 第二层解密后的信息 ([][]bytes{trueKey使用第一层密钥加密后的密文， 使用2_1密码加密后的 第一层密钥, 固定后缀})

	encryptedSplitKeys [][]byte // 第二层分片密钥 5_3加密后的密文
	decryptedSplitKeys [][]byte // 第二层分片密钥 5_3解密后的密文
}

func NewOnlineStartController(version int32) (IController, error) {
	ctx := utils.SetSpanId(context.Background())

	c := &OnlineStartController{
		version:            version,
		updateAt:           time.Now(),
		currentStage:       pb.Stage_WAIT_ONLINE_5_3,
		decryptedSplitKeys: make([][]byte, 5),
	}

	layer2CryptText, encryptedSplitKeys, err := db.GetInfoByVersion(ctx, version)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get version: %v info, err: %v", version, err)
		return nil, ErrKeyManagerInitErr
	}
	if layer2CryptText == nil || len(layer2CryptText) == 0 {
		logger.Error().Ctx(ctx).Msgf("len(layer2CryptText) is 0")
		return nil, ErrKeyManagerInitErr
	}

	if encryptedSplitKeys == nil || len(encryptedSplitKeys) != 5 {
		logger.Error().Ctx(ctx).Msgf("len(encryptedSplitKeys)=%v not 5", len(encryptedSplitKeys))
		return nil, ErrKeyManagerInitErr
	}
	for i, info := range encryptedSplitKeys {
		if info == nil || len(info) == 0 {
			logger.Error().Ctx(ctx).Msgf("index: %v encrypted split key len is 0", i)
			return nil, ErrKeyManagerInitErr
		}
	}

	conf, err := config.GetConfig()
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get config, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}

	encryptKey, err := db.GetClientEncryptKeyByVersion(ctx, version)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when get client encrypt key of version: %v from db, err: %v", version, err.Error())
		return nil, ErrKeyManagerInitErr
	}

	encryptKey, err = crypto.DecryptWithCRC32(encryptKey, conf.EncryptKey)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when decrypt client encrypt key, err: %v", err.Error())
		return nil, ErrKeyManagerInitErr
	}
	encryptKey = crypto.GetDoubleHashByPwd(string(encryptKey))

	c.layer2CryptText = layer2CryptText
	c.encryptedSplitKeys = encryptedSplitKeys
	c.clientEncryptKey = encryptKey
	c.inputPwdSuffix = append([]byte("-----"), encryptKey...)

	return c, nil
}

func (s *OnlineStartController) CanRemove() bool {
	s.timeLock.RLock()
	defer s.timeLock.RUnlock()

	if s.getStage(pb.ClientType_ONLINE_CLIENT_5_3) == pb.Stage_ONLINE_FINISH {
		return true
	}

	return s.updateAt.After(time.Now().Add(30 * time.Minute))
}

func (s *OnlineStartController) GetCurrentState(prefix string) string {
	builder := strings.Builder{}

	s.timeLock.RLock()
	builder.WriteString(fmt.Sprintf("%vlastupdate at: %v\n", prefix, s.updateAt.Format(time.RFC3339)))
	s.timeLock.RUnlock()

	s.stageLock.RLock()
	builder.WriteString(fmt.Sprintf("%vcurrent online stage: %v\n", prefix, s.currentStage))
	s.stageLock.RUnlock()

	s.inputKeyLock.Lock()
	for index, data := range s.decryptedSplitKeys {
		builder.WriteString(fmt.Sprintf("%vonline 5-3 index: %v, is input: %v\n",
			prefix, index+1, data != nil && len(data) >= 0))
	}

	builder.WriteString(fmt.Sprintf("%vonline 2-1 is input: %v\n",
		prefix, s.trueKeys != nil && len(s.trueKeys) >= 0))
	s.inputKeyLock.Unlock()

	s.sendKeyLock.Lock()
	for index, data := range s.trueKeys {
		builder.WriteString(fmt.Sprintf("%vmpc_%v node has fetch data: %v\n",
			prefix, index, s.currentStage == pb.Stage_WAIT_FETCH_DATA_MPC && (data == nil || len(data) == 0)))
	}
	s.sendKeyLock.Unlock()

	builder.WriteString("\n")
	return builder.String()
}

func (s *OnlineStartController) GetStage(ctx context.Context, req *pb.QueryStageRequest) (reply *pb.QueryStageReply) {
	stage := s.getStage(req.ClientType)
	if s.hasInput() {
		s.refreshTime()
	}

	needInput := false

	s.inputKeyLock.Lock()
	if s.currentStage == pb.Stage_WAIT_ONLINE_2_1 && req.ClientType == pb.ClientType_ONLINE_CLIENT_2_1 {
		// 如果是2-1 并且正在等待 2-1 输入, 那么需要输入
		if !s.layer1HasInput {
			needInput = true
		}
	} else if s.currentStage == pb.Stage_WAIT_ONLINE_5_3 && req.ClientType == pb.ClientType_ONLINE_CLIENT_5_3 {
		// 如果是5-3 并且正在等待 5-3 输入, 那么判断当前index是否需要输入
		if s.decryptedSplitKeys[req.ClientIndex-1] == nil || len(s.decryptedSplitKeys[req.ClientIndex-1]) == 0 {
			needInput = true
		}
	}
	s.inputKeyLock.Unlock()

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
		NeedDoubleCheck: false, // 因为是初始化, 所以都需要输入两次密码
		JobFinish:       jobFinish,
	}
}

func (s *OnlineStartController) SubmitKey(ctx context.Context, req *pb.SubmitKeyRequest) *pb.SubmitKeyReply {
	// 是否合法的 clientType
	if req.ClientType != pb.ClientType_ONLINE_CLIENT_5_3 && req.ClientType != pb.ClientType_ONLINE_CLIENT_2_1 {
		logger.Info().Ctx(ctx).Msgf("wrong client type, got: %v", req.ClientType)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("you don't need input")}
	}

	if (req.ClientType == pb.ClientType_ONLINE_CLIENT_5_3) && (req.ClientIndex < 1 || req.ClientIndex > 5) {
		logger.Info().Ctx(ctx).Msgf("wrong client index, got: %v", req.ClientIndex)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("you don't need input")}
	}

	// 先判断是否为当前阶段
	if s.getStage(req.ClientType) != req.Stage {
		logger.Info().Ctx(ctx).Msgf("wrong stage, current: %v, got: %v", s.getStage(req.ClientType), req.Stage)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("not your stage to input")}
	}

	// 只有是当前阶段的人才该输入，其它不应该输入
	if !(req.Stage == pb.Stage_WAIT_ONLINE_2_1 && req.ClientType == pb.ClientType_ONLINE_CLIENT_2_1 ||
		req.Stage == pb.Stage_WAIT_ONLINE_5_3 && req.ClientType == pb.ClientType_ONLINE_CLIENT_5_3) {
		logger.Info().Ctx(ctx).Msgf("wrong stage, current: %v, got: %v", s.getStage(req.ClientType), req.Stage)
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult("not your stage to input")}
	}

	// 解密 密码
	err := s.inputPassword(ctx, req.ClientType, req.ClientIndex, req.KeyData)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when inputPassword, err: %v", err.Error())
		return &pb.SubmitKeyReply{Result: GetFailedRPCResult(err.Error())}
	}

	return &pb.SubmitKeyReply{Result: GetSuccessRPCResult()}
}

func (s *OnlineStartController) FetchData(ctx context.Context, req *pb.FetchDataRequest) (reply *pb.FetchDataReply, canRemove bool) {
	// 是否合法的 clientType
	if req.ClientType != pb.ClientType_CLIENT_MPC {
		return &pb.FetchDataReply{Result: GetFailedRPCResult("you can't fetch data")}, false
	}

	// 判断是否为当前阶段
	if s.getStage(req.ClientType) != req.Stage {
		return &pb.FetchDataReply{Result: GetFailedRPCResult("not your stage to fetch data")}, false
	}

	// 判断签名
	if !s.checkSign(ctx, req) {
		return &pb.FetchDataReply{Result: GetFailedRPCResult("you can't fetch data")}, false
	}

	// 给出数据
	var data []byte
	var err error
	switch req.ClientType {
	case pb.ClientType_CLIENT_MPC:
		s.sendKeyLock.Lock()
		data, err = s.getMPCKey(ctx, req.ClientIndex)
		s.sendKeyLock.Unlock()

		// next 里边有做判断
		s.nextStage()
	default:
		return &pb.FetchDataReply{Result: GetFailedRPCResult("you can't fetch data")}, false
	}

	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when fetch data, err: %v", err.Error())
		return &pb.FetchDataReply{Result: GetFailedRPCResult("error when fetch data")}, false
	}

	canRemove = s.getStage(pb.ClientType_ONLINE_CLIENT_2_1) == pb.Stage_ONLINE_FINISH

	return &pb.FetchDataReply{
		Result: GetSuccessRPCResult(),
		Data:   data,
	}, canRemove
}

func (s *OnlineStartController) refreshTime() {
	s.timeLock.Lock()
	defer s.timeLock.Unlock()
	s.updateAt = time.Now()
}

func (s *OnlineStartController) getStage(clientType pb.ClientType) pb.Stage {
	s.stageLock.RLock()
	defer s.stageLock.RUnlock()

	return s.currentStage
}

func (s *OnlineStartController) nextStage() {
	s.stageLock.Lock()
	defer s.stageLock.Unlock()
	s.refreshTime()

	switch s.currentStage {
	case pb.Stage_WAIT_ONLINE_5_3:
		s.currentStage = pb.Stage_WAIT_ONLINE_2_1
	case pb.Stage_WAIT_ONLINE_2_1:
		s.inputKeyLock.Lock()
		if s.layer1HasInput {
			s.currentStage = pb.Stage_WAIT_FETCH_DATA_MPC
		}
		s.inputKeyLock.Unlock()
	case pb.Stage_WAIT_FETCH_DATA_MPC:
		s.sendKeyLock.Lock()
		if len(s.trueKeys) == 0 {
			s.currentStage = pb.Stage_ONLINE_FINISH
		} else {
			allFetched := true
			for _, data := range s.trueKeys {
				if data != nil || len(data) > 0 {
					allFetched = false
				}
			}
			if allFetched {
				s.currentStage = pb.Stage_ONLINE_FINISH
			}
		}
		s.sendKeyLock.Unlock()
	case pb.Stage_ONLINE_FINISH:
		s.currentStage = pb.Stage_ONLINE_FINISH
	}
}

func (s *OnlineStartController) hasInput() bool {
	s.inputKeyLock.Lock()
	defer s.inputKeyLock.Unlock()

	if len(s.layer2DecryptText) > 0 {
		return true
	}

	for _, info := range s.decryptedSplitKeys {
		if info != nil && len(info) > 0 {
			return true
		}
	}

	return false
}

func (s *OnlineStartController) inputPassword(ctx context.Context, clientType pb.ClientType, index int32, data []byte) error {
	var err error
	data, err = crypto.DecryptWithCRC32(data, s.clientEncryptKey)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf(" error when decrypt client key, err: %v", err.Error())
		return fmt.Errorf("client version mismatch, please update client binary")
	}
	if !bytes.HasSuffix(data, s.inputPwdSuffix) {
		logger.Info().Ctx(ctx).Msgf("client type: %v, index: %v not use target communicate key, need check")
		return fmt.Errorf("client communicate key error, please recheck communicate key")
	} else {
		data = bytes.TrimSuffix(data, s.inputPwdSuffix)
	}

	data = crypto.GetDoubleHashByPwd(string(data))

	switch clientType {
	case pb.ClientType_ONLINE_CLIENT_2_1:
		s.inputKeyLock.Lock()

		// 判断是否已经输入密码
		if s.layer1HasInput {
			s.inputKeyLock.Unlock()
			return fmt.Errorf("you already input password")
		}

		err = s.do21Decrypt(ctx, data)
		if err != nil {
			s.inputKeyLock.Unlock()
			return err
		}
		s.layer1HasInput = true
		s.inputKeyLock.Unlock()
		s.nextStage()

	case pb.ClientType_ONLINE_CLIENT_5_3:
		s.inputKeyLock.Lock()

		// 判断是否已经输入密码
		if s.decryptedSplitKeys[index-1] != nil && len(s.decryptedSplitKeys[index-1]) > 0 {
			s.inputKeyLock.Unlock()
			return fmt.Errorf("you already input password")
		}

		info, err := s.do53Decrypt(ctx, index, s.encryptedSplitKeys[index-1], data)
		if err != nil {
			s.inputKeyLock.Unlock()
			return err
		}
		s.decryptedSplitKeys[index-1] = info

		// 满足3个人就可以进行下一步了
		count := 0
		for _, decryptData := range s.decryptedSplitKeys {
			if decryptData != nil && len(decryptData) > 0 {
				count++
			}
		}
		if count >= 3 {
			err = s.decryptLayer2Text(ctx)
			if err != nil {
				return err
			}
		}
		s.inputKeyLock.Unlock()

		if count >= 3 {
			s.nextStage()
		}

	default:
		return fmt.Errorf("you don't need input")
	}

	return nil
}

func (s *OnlineStartController) do21Decrypt(ctx context.Context, key []byte) (err error) {
	if len(s.layer2DecryptText) != 3 {
		logger.Info().Ctx(ctx).Msgf("layer2 decrypt text length is not 3")
		return fmt.Errorf("key manager error")
	}

	layer1EncryptKey, err := crypto.DecryptWithCRC32(s.layer2DecryptText[1], key)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when decrypt, err: %v", err.Error())
		return fmt.Errorf("wrong password, please check")
	}

	if !bytes.HasSuffix(layer1EncryptKey, common.KeyManagerDefaultSuffix) {
		logger.Error().Ctx(ctx).Msgf("layer1EncryptKey suffix doesn't equal fixedSuffix")
		return fmt.Errorf("wrong password, please check")
	} else {
		layer1EncryptKey = bytes.TrimSuffix(layer1EncryptKey, common.KeyManagerDefaultSuffix)
	}

	layer1Info, err := crypto.DecryptWithCRC32(s.layer2DecryptText[0], layer1EncryptKey)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when decrypt layer 1 info, err: %v", err.Error())
		return fmt.Errorf("key manager error")
	}

	trueKeys, err := getGobDecodeSlice(ctx, layer1Info)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when gob decode layer1 info, err: %v", err.Error())
		return fmt.Errorf("key manager error")
	}

	if len(trueKeys) != 6 {
		logger.Error().Ctx(ctx).Msgf("true key length is not 6")
		return fmt.Errorf("key manager error")
	}
	if !bytes.Equal(trueKeys[len(trueKeys)-1], common.KeyManagerDefaultSuffix) {
		logger.Error().Ctx(ctx).Msgf("trueKey suffix not equal")
		return fmt.Errorf("key manager error")
	}

	s.trueKeys = trueKeys[:5]
	return nil
}

func (s *OnlineStartController) do53Decrypt(ctx context.Context, index int32, data, key []byte) (result []byte, err error) {
	result, err = crypto.DecryptWithCRC32(data, key)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when decrypt, err: %v", err.Error())
		return nil, fmt.Errorf("wrong password, please check")
	}

	infoSlice, err := getGobDecodeSlice(ctx, result)
	if !bytes.Equal(infoSlice[len(infoSlice)-1], common.KeyManagerDefaultSuffix) {
		logger.Info().Ctx(ctx).Msgf("index: %v, suffix doesn't equal fixedSuffix", index)
		return nil, fmt.Errorf("wrong password, please check")
	}

	return result, nil
}

func (s *OnlineStartController) decryptLayer2Text(ctx context.Context) error {
	// 组合 5-3 解密后的 layer2 分片密钥 得到 layer2 密钥
	layer2EncryptKey, err := CombineSplitKey(ctx, s.decryptedSplitKeys)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when combine split keys, err: %v", err.Error())
		return fmt.Errorf("key manager error")
	}

	// 使用 layer2 密钥解密 layer2Text
	data, err := crypto.DecryptWithCRC32(s.layer2CryptText, layer2EncryptKey)
	layer2DecryptTextSlice, err := getGobDecodeSlice(ctx, data)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when gob.decode to get slice, err: %v", err.Error())
		return fmt.Errorf("key manager error")
	}

	if len(layer2DecryptTextSlice) != 3 {
		logger.Error().Ctx(ctx).Msgf("layer2DecryptTextSlice length is not 3")
		return fmt.Errorf("key manager error")
	}

	if !bytes.Equal(layer2DecryptTextSlice[2], common.KeyManagerDefaultSuffix) {
		logger.Error().Ctx(ctx).Msgf("layer2DecryptTextSlice suffix doesn't equal fixedSuffix")
		return fmt.Errorf("key manager error")
	}

	s.layer2DecryptText = layer2DecryptTextSlice
	return nil
}

func (s *OnlineStartController) checkSign(ctx context.Context, req *pb.FetchDataRequest) bool {
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

func (s *OnlineStartController) getMPCKey(ctx context.Context, index int32) (data []byte, err error) {
	if index < 1 || index > 5 {
		logger.Info().Ctx(ctx).Msgf("wrong index, want 1-5 got: %v", index)
		return nil, fmt.Errorf("can't fetch data")
	}

	trueKey := s.trueKeys[index-1]
	if len(trueKey) == 0 {
		logger.Info().Ctx(ctx).Msgf("empty true key")
		return nil, fmt.Errorf("can't fetch data")
	}

	info := common.SyncMPCNodeNeedMsg{
		TrueKey: trueKey,
	}

	s.trueKeys[index-1] = nil

	data, err = utils.GobEncode(info)
	if err != nil {
		logger.Info().Ctx(ctx).Msgf("error when gob encode, err: %v", err.Error())
		return nil, fmt.Errorf("can't fetch data")
	}

	return data, nil
}

func CombineSplitKey(ctx context.Context, splitKeys [][]byte) ([]byte, error) {
	key := make([][]byte, 10)
	for index, keys := range splitKeys {
		if keys == nil || len(keys) == 0 {
			continue
		}
		keySlice, err := getGobDecodeSlice(ctx, keys)
		if err != nil {
			return nil, err
		}

		for i, splitKeyIndex := range common.SplitKeysIndex[index] {
			key[splitKeyIndex] = keySlice[i]
		}
	}

	h := sha256.New()
	for _, k := range key {
		h.Write(k)
	}

	return h.Sum(nil), nil
}

func getGobDecodeSlice(ctx context.Context, info []byte) (result [][]byte, err error) {
	buf := bytes.Buffer{}
	decoder := gob.NewDecoder(&buf)

	buf.Write(info)
	err = decoder.Decode(&result)
	if err != nil {
		logger.Error().Ctx(ctx).Msgf("error when decode info, err: %v", err.Error())
		return
	}

	return
}
