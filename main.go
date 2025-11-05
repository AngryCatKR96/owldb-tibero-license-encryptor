package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"golang.org/x/net/html/charset"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ==== 인터페이스 정의 ====
// 각 컴포넌트의 역할을 명확히 정의합니다

// ConfigReader는 설정을 읽는 역할을 담당합니다
type ConfigReader interface {
	ReadConfig(filePath string) error
	GetEncryptionKey() string
	GetAlgorithm() string
	GetGCMIVLength() int
	GetGCMTagLength() int
}

// LicenseParser는 라이센스 파일을 파싱하는 역할을 담당합니다
type LicenseParser interface {
	ParseXML(content []byte) (*TiberoLicense, error)
}

// Encryptor는 암호화 기능을 담당합니다
type Encryptor interface {
	Encrypt(plaintext []byte) (string, error)
}

// FileManager는 파일 읽기/쓰기를 담당합니다
type FileManager interface {
	ReadXMLFiles(dir string) ([]*LicenseFile, error)
	SaveEncryptedFile(content string, outputPath string) error
}

// ==== 구조체 정의 ====

// TiberoLicense와 관련 구조체들 (원본과 동일)
type TiberoLicense struct {
	XMLName xml.Name `xml:"tmax_license"`
	License License  `xml:"license"`
}

type License struct {
	Version         string  `xml:"version,attr"`
	Product         Product `xml:"product"`
	SerialID        string  `xml:"serial_ID"`
	IssueDate       string  `xml:"issue_date"`
	StartDate       string  `xml:"start_date"`
	EndDate         string  `xml:"end_date"`
	Licensee        string  `xml:"licensee"`
	Edition         string  `xml:"edition"`
	Type            string  `xml:"type"`
	Duration        string  `xml:"duration"`
	LimitCPU        string  `xml:"limit_cpu"`
	Topology        string  `xml:"topology"`
	IdentifiedByCSP string  `xml:"identified_by_csp_name"`
	Signature       string  `xml:"signature"`
}

type Product struct {
	Version string `xml:"version,attr"`
	Name    string `xml:",chardata"`
}

// ==== 설정 관리 클래스 ====
// 설정을 읽고 관리하는 책임을 가집니다
type YAMLConfigManager struct {
	encryptionKey string
	algorithm     string
	gcmIVLength   int
	gcmTagLength  int
}

// ReadConfig은 YAML 설정 파일을 읽어서 내부 상태를 설정합니다
func (c *YAMLConfigManager) ReadConfig(filePath string) error {
	// YAML 파일 구조 정의 (내부에서만 사용)
	type yamlStructure struct {
		License struct {
			EncryptionKey string `yaml:"encryption-key"`
			Algorithm     string `yaml:"algorithm"`
			GCMIVLength   int    `yaml:"gcm-iv-length"`
			GCMTagLength  int    `yaml:"gcm-tag-length"`
		} `yaml:"license"`
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("YAML 파일을 읽을 수 없습니다: %w", err)
	}

	var config yamlStructure
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("YAML 파싱 오류: %w", err)
	}

	// 유효성 검증
	if config.License.EncryptionKey == "" {
		return fmt.Errorf("암호화 키가 설정되지 않았습니다")
	}
	if config.License.Algorithm != "AES/GCM/NoPadding" {
		return fmt.Errorf("지원하지 않는 알고리즘: %s", config.License.Algorithm)
	}

	// base64 디코딩
	keyBytes, err := base64.StdEncoding.DecodeString(config.License.EncryptionKey)
	if err != nil {
		return fmt.Errorf("암호화 키 디코딩 실패: %w", err)
	}

	// 내부 상태 설정
	c.encryptionKey = string(keyBytes)
	c.algorithm = config.License.Algorithm
	c.gcmIVLength = config.License.GCMIVLength
	c.gcmTagLength = config.License.GCMTagLength

	return nil
}

// Getter 메서드들
func (c *YAMLConfigManager) GetEncryptionKey() string { return c.encryptionKey }
func (c *YAMLConfigManager) GetAlgorithm() string     { return c.algorithm }
func (c *YAMLConfigManager) GetGCMIVLength() int      { return c.gcmIVLength }
func (c *YAMLConfigManager) GetGCMTagLength() int     { return c.gcmTagLength }

// ==== 라이센스 파일 클래스 ====
// 라이센스 파일 정보와 관련 기능을 캡슐화합니다
type LicenseFile struct {
	path    string
	name    string
	content []byte
	license *TiberoLicense // 파싱된 라이센스 정보
}

// NewLicenseFile은 새로운 LicenseFile 인스턴스를 생성합니다
func NewLicenseFile(path, name string, content []byte) *LicenseFile {
	return &LicenseFile{
		path:    path,
		name:    name,
		content: content,
	}
}

// GetPath는 파일 경로를 반환합니다
func (lf *LicenseFile) GetPath() string { return lf.path }

// GetName은 파일 이름을 반환합니다
func (lf *LicenseFile) GetName() string { return lf.name }

// GetContent는 파일 내용을 반환합니다
func (lf *LicenseFile) GetContent() []byte { return lf.content }

// Parse는 XML 내용을 파싱하여 라이센스 정보를 추출합니다
func (lf *LicenseFile) Parse() error {
	parser := &DefaultLicenseParser{}
	license, err := parser.ParseXML(lf.content)
	if err != nil {
		return fmt.Errorf("라이센스 파싱 실패 (%s): %w", lf.name, err)
	}
	lf.license = license
	return nil
}

// GetOutputFileName은 라이센스의 시작 날짜를 기반으로 출력 파일명을 생성합니다
func (lf *LicenseFile) GetOutputFileName() (string, error) {
	if lf.license == nil {
		return "", fmt.Errorf("라이센스가 파싱되지 않았습니다")
	}

	t, err := time.Parse("2006/01/02", lf.license.License.StartDate)
	if err != nil {
		return "", fmt.Errorf("날짜 파싱 오류: %w", err)
	}

	return t.Format("20060102") + ".txt", nil
}

// ==== 라이센스 파서 클래스 ====
// XML 파싱 책임을 담당합니다
type DefaultLicenseParser struct{}

func (p *DefaultLicenseParser) ParseXML(content []byte) (*TiberoLicense, error) {
	var license TiberoLicense

	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	decoder.CharsetReader = charset.NewReaderLabel

	err := decoder.Decode(&license)
	if err != nil {
		return nil, fmt.Errorf("XML 디코딩 오류: %w", err)
	}

	return &license, nil
}

// ==== AES-GCM 암호화 클래스 ====
// 암호화 기능을 캡슐화합니다
type AESGCMEncryptor struct {
	key       string
	ivLength  int
	tagLength int
}

// NewAESGCMEncryptor는 새로운 암호화 인스턴스를 생성합니다
func NewAESGCMEncryptor(key string, ivLength, tagLength int) *AESGCMEncryptor {
	return &AESGCMEncryptor{
		key:       key,
		ivLength:  ivLength,
		tagLength: tagLength,
	}
}

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) (string, error) {
	keyBytes := []byte(e.key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("AES 암호 생성 실패: %w", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, e.ivLength)
	if err != nil {
		return "", fmt.Errorf("GCM 모드 생성 실패: %w", err)
	}

	nonce := make([]byte, e.ivLength)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("난수 생성 실패: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := append(nonce, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// ==== 파일 관리 클래스 ====
// 파일 읽기/쓰기 책임을 담당합니다
type DefaultFileManager struct{}

func (fm *DefaultFileManager) ReadXMLFiles(dir string) ([]*LicenseFile, error) {
	var xmlFiles []*LicenseFile

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("디렉토리가 존재하지 않습니다: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("디렉토리를 읽을 수 없습니다: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileName := entry.Name()
		if strings.HasSuffix(strings.ToLower(fileName), ".xml") {
			fullPath := filepath.Join(dir, fileName)

			content, err := os.ReadFile(fullPath)
			if err != nil {
				log.Printf("경고: %s 파일을 읽을 수 없습니다: %v", fullPath, err)
				continue
			}

			xmlFile := NewLicenseFile(fullPath, fileName, content)
			xmlFiles = append(xmlFiles, xmlFile)
			log.Printf("XML 파일 읽음: %s (%d 바이트)", fileName, len(content))
		}
	}

	return xmlFiles, nil
}

func (fm *DefaultFileManager) SaveEncryptedFile(content string, outputPath string) error {
	// 이중 base64 인코딩 (원본 코드와 동일한 동작)
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(content))

	err := os.WriteFile(outputPath, []byte(doubleEncoded), 0644)
	if err != nil {
		return fmt.Errorf("파일 저장 실패: %w", err)
	}
	return nil
}

// ==== 라이센스 암호화 서비스 클래스 ====
// 전체 라이센스 암호화 프로세스를 관리합니다
type LicenseEncryptionService struct {
	configReader ConfigReader
	fileManager  FileManager
	encryptor    Encryptor
}

// NewLicenseEncryptionService는 새로운 서비스 인스턴스를 생성합니다
func NewLicenseEncryptionService(configReader ConfigReader, fileManager FileManager, encryptor Encryptor) *LicenseEncryptionService {
	return &LicenseEncryptionService{
		configReader: configReader,
		fileManager:  fileManager,
		encryptor:    encryptor,
	}
}

// ProcessLicenses는 라이센스 파일들을 처리합니다
func (s *LicenseEncryptionService) ProcessLicenses(licenseFilesDir, outputDir string) error {
	// XML 파일들을 읽어옵니다
	xmlFiles, err := s.fileManager.ReadXMLFiles(licenseFilesDir)
	if err != nil {
		return fmt.Errorf("XML 파일 읽기 실패: %w", err)
	}

	log.Printf("총 %d개의 XML 파일을 찾았습니다.", len(xmlFiles))

	// 출력 디렉토리를 생성합니다
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		return fmt.Errorf("출력 디렉토리 생성 실패: %w", err)
	}

	successCount := 0
	for i, xmlFile := range xmlFiles {
		log.Printf("[%d/%d] 처리 중: %s", i+1, len(xmlFiles), xmlFile.GetName())

		err := s.processLicenseFile(xmlFile, outputDir)
		if err != nil {
			log.Printf("오류: %v", err)
			continue
		}

		successCount++
	}

	log.Printf("처리 완료: %d/%d 파일 성공", successCount, len(xmlFiles))
	return nil
}

// processLicenseFile은 개별 라이센스 파일을 처리합니다 (private 메서드)
func (s *LicenseEncryptionService) processLicenseFile(licenseFile *LicenseFile, outputDir string) error {
	// 라이센스를 파싱합니다
	err := licenseFile.Parse()
	if err != nil {
		return err
	}

	// 원본 XML 내용을 암호화합니다
	encrypted, err := s.encryptor.Encrypt(licenseFile.GetContent())
	if err != nil {
		return fmt.Errorf("암호화 실패: %w", err)
	}

	// 출력 파일명을 생성합니다
	fileName, err := licenseFile.GetOutputFileName()
	if err != nil {
		return fmt.Errorf("파일명 생성 실패: %w", err)
	}

	// 출력 파일 경로를 생성합니다
	outputPath := filepath.Join(outputDir, fileName)

	// 암호화된 내용을 저장합니다
	err = s.fileManager.SaveEncryptedFile(encrypted, outputPath)
	if err != nil {
		return err
	}

	log.Printf("암호화 완료: %s -> %s", licenseFile.GetName(), fileName)
	return nil
}

// ==== 메인 애플리케이션 클래스 ====
// 전체 애플리케이션의 생명주기를 관리합니다
type LicenseEncryptorApp struct {
	service *LicenseEncryptionService
}

// NewLicenseEncryptorApp은 새로운 애플리케이션 인스턴스를 생성합니다
func NewLicenseEncryptorApp() *LicenseEncryptorApp {
	// 의존성을 주입합니다
	configReader := &YAMLConfigManager{}
	fileManager := &DefaultFileManager{}

	// 암호화기는 설정을 읽은 후에 생성해야 하므로 나중에 설정됩니다
	service := NewLicenseEncryptionService(configReader, fileManager, nil)

	return &LicenseEncryptorApp{
		service: service,
	}
}

// Run은 애플리케이션을 실행합니다
func (app *LicenseEncryptorApp) Run(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("사용법: program <cspType> <licenseFilesDir> <owlDbProjectDir>")
	}

	cspType := args[1]
	licenseFilesDir := args[2]
	owlDbProjectDir := args[3]

	log.Printf("CSP Type: %s", cspType)
	log.Printf("License Files Directory: %s", licenseFilesDir)
	log.Printf("OWL DB Project Directory: %s", owlDbProjectDir)

	// YAML 설정을 읽습니다
	yamlPath := filepath.Join(owlDbProjectDir, "src", "main", "resources", "application-prod.yml")
	log.Printf("Reading configuration from: %s", yamlPath)

	err := app.service.configReader.ReadConfig(yamlPath)
	if err != nil {
		return fmt.Errorf("설정 파일 읽기 실패: %w", err)
	}

	// 설정이 읽힌 후 암호화기를 생성합니다
	encryptor := NewAESGCMEncryptor(
		app.service.configReader.GetEncryptionKey(),
		app.service.configReader.GetGCMIVLength(),
		app.service.configReader.GetGCMTagLength(),
	)
	app.service.encryptor = encryptor

	log.Printf("암호화 설정 로드 완료:")
	log.Printf("  - 알고리즘: %s", app.service.configReader.GetAlgorithm())
	log.Printf("  - IV 길이: %d", app.service.configReader.GetGCMIVLength())
	log.Printf("  - 태그 길이: %d", app.service.configReader.GetGCMTagLength())

	// 출력 디렉토리 경로를 생성합니다
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("실행 파일 경로를 가져올 수 없습니다: %w", err)
	}
	outputDir := filepath.Join(filepath.Dir(execPath), cspType)

	// 라이센스들을 처리합니다
	return app.service.ProcessLicenses(licenseFilesDir, outputDir)
}

func main() {
	log.Println("Starting LI License Encryptor...")

	app := NewLicenseEncryptorApp()
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("애플리케이션 실행 실패: %v", err)
	}

	log.Println("License Encryptor 종료.")
}
