// ============================================================================
// FLL CHALLENGE CẤP TRƯỜNG - TRƯỜNG THCS & THPT ĐINH THIỆN LÝ (LSTS)
// MÙA GIẢI BIOGLOW | HỆ THỐNG CHẤM ĐIỂM, TỔNG HỢP & CÔNG BỐ KẾT QUẢ
// ============================================================================

const STORAGE_KEY = "LSTS_FLL_BIOGLOW_DATA_V1";
const CLOUD_CFG_KEY = "LSTS_FLL_BIOGLOW_CLOUD_CFG";
const SESSION_KEY = "LSTS_FLL_BIOGLOW_SESSION_V1";
const AUTH_SALT = "LSTS_BIOGLOW_2026_SECURE_SALT_#9981";
const KEY_STRETCH_ROUNDS = 20000; // Lặp 20.000 vòng SHA-256 (Key Stretching / PBKDF2) chống dò mật khẩu bằng từ điển

// Khởi tạo trước hằng số nguyên tố SHA-256 để chạy 20.000 vòng băm mượt mà
const SHA256_H_INIT = [];
const SHA256_K_INIT = [];
(function initSha256Constants() {
  const mathPow = Math.pow, maxWord = mathPow(2, 32);
  let primeCounter = 0;
  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
      SHA256_H_INIT[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      SHA256_K_INIT[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
})();

// Hàm băm mật mã một chiều SHA-256
function sha256Hash(ascii) {
  function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
  const maxWord = 4294967296;
  let i, j, result = "";
  const words = [], asciiBitLength = ascii.length * 8;
  let hash = SHA256_H_INIT.slice(0, 8);
  const k = SHA256_K_INIT;

  ascii += "\x80";
  while ((ascii.length % 64) - 56) ascii += "\x00";
  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;
  for (j = 0; j < words.length; ) {
    const w = words.slice(j, (j += 16)), oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
      const temp1 =
        hash[7] +
        (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
        ((e & hash[5]) ^ (~e & hash[6])) +
        k[i] +
        (w[i] =
          i < 16
            ? w[i]
            : (w[i - 16] +
                (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                w[i - 7] +
                (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
              0);
      const temp2 =
        (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
        ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }
  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? 0 : "") + b.toString(16);
    }
  }
  return result;
}

// Hàm kéo giãn khóa (Key Stretching / PBKDF2-SHA256) với 20.000 vòng lặp
function stretchHash(val, salt = AUTH_SALT, rounds = KEY_STRETCH_ROUNDS) {
  let h = sha256Hash(`${salt}:${val}`);
  for (let i = 0; i < rounds; i++) {
    h = sha256Hash(`${h}:${i & 0xff}`);
  }
  return h;
}

// Danh sách chứng thực Dự phòng Offline đã qua Key Stretching 20.000 vòng SHA-256.
// Lưu ý: Khi đã triển khai Google Apps Script làm Backend chính thức, bạn có thể để mảng này rỗng (const OFFLINE_AUTH_RECORDS = [];)
// vì toàn bộ việc kiểm tra uHash, pHash và phân quyền RG / RUBRIC / ADMIN đã được thực thi trực tiếp trên Google Cloud (doPost).
const OFFLINE_AUTH_RECORDS = [
  { userHash: "45883525e1591191bb9b00bf7937a9719a235093724fd735580dac8d2b7d0ac4", passHash: "d4eec93af2cc45cd665264087f57b2700ce7b4dfaa9505cb00dbdcd5d1025633", role: "RG" },
  { userHash: "2c733fda1d0b36419d8c7aa3cc2edf46680b83549a161c305bb06527d4eda092", passHash: "dba1e130ae56525206bfeba8be1bb9edcf110c9b9e5cec7fb9ab1018a599b6bc", role: "RG" },
  { userHash: "87b5c72305925376776716c8d7c854e25bf0c5b57ca301cd00b1a57ce8f92848", passHash: "4bcaa42ba8d11bef71f821e03656d1dfcae41099c2bc5a7de4c27f8e2be474a7", role: "RG" },
  { userHash: "ade05f4a9d970b4dd95783681dad5426fb2dd2d282a50f54421a4898befc71c4", passHash: "2c15747696d3b94c2f839d014f78b93acf308f2efe062e70895813c715869abd", role: "RG" },
  { userHash: "ca44a527193d9eaaa57796f6deff1c5a2d05d1d4b29ee2348b2f49b99433e1f7", passHash: "c05a39f5d9345c4da2efbae4ef98808fbde7b55f534aa38c76e4f468124be27c", role: "RUBRIC" },
  { userHash: "11b5b9aedc3be186821ffddb66a8fce79b83d00afd983129e04e34bdc0ef009e", passHash: "ef500e76b326a671a333720bb275f966cf13d2eafb77d3360b9e3c62ca575d2c", role: "RUBRIC" },
  { userHash: "402bbb2f187292c3ebc3da0741f3d901154447198fb6786ffbc17bebb9f4b36d", passHash: "d1095a7739a3276c1e41519fc13d9565d0c0e1d40a3f1d166b7be5e35e071843", role: "RUBRIC" },
  { userHash: "5eb79ff615bce9b2f300a5191384b4e703865c0d358b2e33e672d9916ae30863", passHash: "ae688bd607d97101b247546ec3109f9387072a94c2a3b72c8d75567feaa02454", role: "RUBRIC" },
  { userHash: "ff1db46bca23c14e5f95f39c4eace808375c42454608b2a537a77832840f0c72", passHash: "a108786d149488709d0e724e404275817d357897b5ca956d45e216c8b398b996", role: "ADMIN" }
];

// Cấu trúc tiêu chí Robot Game [BM01-RG] (110 điểm)
const RG_CRITERIA = [
  { group: "NHIỆM VỤ 1 (MISSION 1): MANG VẬT QUA ĐƯỜNG ZICZAC ĐẾN GOAL 1 (20 điểm)", items: [
    { code: "M1_1", label: "M1.1", title: "Robot mang vật xuất phát từ khu vực HOME", cond: "Robot mang theo vật rời khỏi vạch HOME hợp lệ", pts: 5 },
    { code: "M1_2", label: "M1.2", title: "Robot di chuyển vượt qua đường ziczac", cond: "Vượt qua khu vực đường ziczac đúng lộ trình", pts: 5 },
    { code: "M1_3", label: "M1.3", title: "Giữ vật ổn định, không bị rơi", cond: "Vật không rơi khỏi robot trong suốt hành trình", pts: 5 },
    { code: "M1_4", label: "M1.4", title: "Đưa vật vào khu vực đích GOAL 1", cond: "Chỉ tính khi vật nằm HOÀN TOÀN trong GOAL 1", pts: 5 }
  ]},
  { group: "NHIỆM VỤ 2 (MISSION 2): TIẾP CẬN, NÂNG/MÓC KIỆN HÀNG VÀO GOAL 2 (30 điểm)", items: [
    { code: "M2_1", label: "M2.1", title: "Robot tiếp cận kiện hàng tại khu vực Mission 2", cond: "Di chuyển đến đúng vị trí tiếp cận kiện hàng", pts: 5 },
    { code: "M2_2", label: "M2.2", title: "Nâng hoặc móc kiện hàng thành công", cond: "Kéo hoặc nâng kiện hàng đều được chấp nhận", pts: 10 },
    { code: "M2_3", label: "M2.3", title: "Di chuyển kiện hàng về hướng đích GOAL 2", cond: "Kiện hàng được kéo/nâng rời vị trí ban đầu", pts: 5 },
    { code: "M2_4", label: "M2.4", title: "Đưa kiện hàng vào khu vực đích GOAL 2", cond: "Trạng thái cuối: Kiện hàng nằm tại đích GOAL 2", pts: 10 }
  ]},
  { group: "NHIỆM VỤ 3 (MISSION 3): DÒ LINE TỰ ĐỘNG & PHÂN LOẠI VẬT ĐỎ / XANH (50 điểm)", items: [
    { code: "M3_1", label: "M3.1", title: "Robot thực hiện dò line tự động", cond: "Vận hành tự động bám theo vạch line trên sa bàn", pts: 15 },
    { code: "M3_2", label: "M3.2", title: "Đẩy vật ĐỎ sang khu vực bên TRÁI", cond: "Trạng thái cuối: Vật đỏ nằm đúng phía bên trái", pts: 15 },
    { code: "M3_3", label: "M3.3", title: "Đẩy vật XANH sang khu vực bên PHẢI", cond: "Trạng thái cuối: Vật xanh nằm đúng phía bên phải", pts: 15 },
    { code: "M3_4", label: "M3.4", title: "Robot di chuyển đến khu vực đích GOAL 3", cond: "Trạng thái cuối: Robot dừng tại khu vực GOAL 3", pts: 5 }
  ]},
  { group: "ĐIỂM THƯỞNG XUẤT SẮC – EXCELLENCE BONUS (10 điểm)", items: [
    { code: "EB_1", label: "EB.1", title: "Continuous Run (Vận hành liên tục)", cond: "Hoàn thành liên tục các nhiệm vụ trong lượt chạy", pts: 5 },
    { code: "EB_2", label: "EB.2", title: "No Human Intervention (Không can thiệp)", cond: "Không có sự can thiệp của người điều khiển", pts: 5 }
  ]}
];

// Cấu trúc tiêu chí Thiết Kế Robot [BM04-RD] (40 điểm, 5 tiêu chí CV = 20 điểm)
const RD_SECTIONS = [
  {
    section: "1. XÁC ĐỊNH",
    desc: "Nhóm đã xác định những nhiệm vụ cần thực hiện, tìm hiểu các nguồn lực về xây dựng và lập trình, và tìm kiếm sự hướng dẫn khi cần thiết.",
    rows: [
      { code: "1.1", isCV: false, l1: "Bằng chứng về chiến lược nhiệm vụ rất hạn chế.", l2: "Bằng chứng một phần về chiến lược nhiệm vụ.", l3: "Bằng chứng rõ ràng về chiến lược nhiệm vụ." },
      { code: "1.2", isCV: true,  l1: "Sử dụng tối thiểu tài nguyên xây dựng hoặc lập trình.", l2: "Một số công việc liên quan đến xây dựng hoặc lập trình.", l3: "Sử dụng rõ ràng các nguồn lực xây dựng hoặc lập trình để hỗ trợ chiến lược sứ mệnh của họ." }
    ]
  },
  {
    section: "2. THIẾT KẾ",
    desc: "Các thành viên trong nhóm đã cùng nhau hợp tác thiết kế và phát triển các kỹ năng xây dựng và lập trình cần thiết.",
    rows: [
      { code: "2.1", isCV: true,  l1: "Có rất ít bằng chứng cho thấy tất cả các thành viên đều đóng góp ý tưởng.", l2: "Một phần bằng chứng cho thấy tất cả các thành viên đều đóng góp ý tưởng.", l3: "Có bằng chứng rõ ràng cho thấy tất cả các thành viên đều đóng góp ý tưởng." },
      { code: "2.2", isCV: false, l1: "Hầu như không có bằng chứng nào cho thấy các thành viên có kỹ năng xây dựng và lập trình.", l2: "Một phần bằng chứng về kỹ năng xây dựng và lập trình của tất cả các thành viên.", l3: "Có bằng chứng rõ ràng về kỹ năng xây dựng và lập trình của tất cả các thành viên." }
    ]
  },
  {
    section: "3. SÁNG TẠO",
    desc: "Nhóm đã phát triển các thiết kế mới hoặc cải tiến các thiết kế hiện có dựa trên chiến lược nhiệm vụ của mình.",
    rows: [
      { code: "3.1", isCV: false, l1: "Giải thích không rõ ràng về các phụ kiện đính kèm và mục đích của chúng.", l2: "Giải thích đơn giản về các phụ kiện đính kèm và mục đích của chúng.", l3: "Giải thích rõ ràng về các phụ kiện cải tiến và mục đích của chúng." },
      { code: "3.2", isCV: false, l1: "Giải thích không rõ ràng về cách sử dụng mã lập trình và/hoặc cảm biến.", l2: "Giải thích đơn giản về cách sử dụng mã lập trình và/hoặc cảm biến.", l3: "Giải thích rõ ràng về việc sử dụng mã lập trình và/hoặc cảm biến tiên tiến." }
    ]
  },
  {
    section: "4. LẶP LẠI",
    desc: "Nhóm đã liên tục thử nghiệm robot và mã lập trình của mình để xác định các lĩnh vực cần cải thiện và tích hợp những phát hiện đó vào giải pháp của họ.",
    rows: [
      { code: "4.1", isCV: false, l1: "Có rất ít bằng chứng cho thấy nhóm đã thử nghiệm robot và mã lập trình của mình.", l2: "Một phần bằng chứng về việc nhóm thử nghiệm robot và mã lập trình của mình.", l3: "Có bằng chứng rõ ràng về việc nhóm thử nghiệm robot và mã lập trình nhiều lần." },
      { code: "4.2", isCV: true,  l1: "Kết quả thử nghiệm cho thấy có rất ít bằng chứng về sự cải thiện.", l2: "Một phần bằng chứng về sự cải thiện dựa trên thử nghiệm.", l3: "Có bằng chứng rõ ràng về sự cải thiện dựa trên kết quả kiểm tra." }
    ]
  },
  {
    section: "5. GIAO TIẾP",
    desc: "Nhóm đã trình bày một cách hiệu quả những gì họ học được từ quá trình thiết kế robot và ăn mừng những tiến bộ đạt được.",
    rows: [
      { code: "5.1", isCV: true,  l1: "Giải thích về quy trình và bài học kinh nghiệm chưa rõ ràng.", l2: "Giải thích đơn giản về quy trình và những bài học kinh nghiệm.", l3: "Giải thích chi tiết về quy trình và những bài học kinh nghiệm." },
      { code: "5.2", isCV: true,  l1: "Nhóm thể hiện sự thiếu tự hào hoặc nhiệt tình đối với công việc của mình.", l2: "Nhóm thể hiện một phần niềm tự hào hoặc sự nhiệt tình đối với công việc của mình.", l3: "Cả nhóm thể hiện rõ niềm tự hào hoặc sự nhiệt tình đối với công việc của mình." }
    ]
  }
];

// Cấu trúc tiêu chí Dự Án Đổi Mới [BM05-IP] (40 điểm, 5 tiêu chí CV = 20 điểm)
const IP_SECTIONS = [
  {
    section: "1. XÁC ĐỊNH",
    desc: "Nhóm đã xác định rõ một vấn đề và đã nghiên cứu kỹ lưỡng vấn đề đó.",
    rows: [
      { code: "1.1", isCV: false, l1: "Định nghĩa vấn đề không rõ ràng.", l2: "Định nghĩa vấn đề chưa được rõ ràng hoàn toàn.", l3: "Định nghĩa rõ ràng về vấn đề." },
      { code: "1.2", isCV: true,  l1: "Có rất ít bằng chứng nghiên cứu.", l2: "Bằng chứng một phần về nghiên cứu từ một hoặc nhiều nguồn.", l3: "Nghiên cứu rõ ràng, chi tiết từ nhiều nguồn khác nhau." }
    ]
  },
  {
    section: "2. THIẾT KẾ",
    desc: "Cả nhóm đã cùng nhau lập kế hoạch dự án và phát triển ý tưởng.",
    rows: [
      { code: "2.1", isCV: false, l1: "Có rất ít bằng chứng về một kế hoạch dự án hiệu quả.", l2: "Một phần bằng chứng về kế hoạch dự án hiệu quả.", l3: "Bằng chứng rõ ràng về một kế hoạch dự án hiệu quả." },
      { code: "2.2", isCV: true,  l1: "Có rất ít bằng chứng cho thấy quá trình phát triển có sự tham gia của tất cả thành viên.", l2: "Một phần bằng chứng cho thấy quá trình phát triển có sự tham gia của tất cả các thành viên.", l3: "Có bằng chứng rõ ràng cho thấy quá trình phát triển có sự tham gia của tất cả các thành viên." }
    ]
  },
  {
    section: "3. SÁNG TẠO",
    desc: "Nhóm đã phát triển một ý tưởng độc đáo hoặc xây dựng trên một ý tưởng hiện có với mô hình/bản vẽ nguyên mẫu để thể hiện giải pháp của mình.",
    rows: [
      { code: "3.1", isCV: true,  l1: "Giải thích tối thiểu về sự đổi mới trong giải pháp.", l2: "Giải thích đơn giản về sự đổi mới trong giải pháp.", l3: "Giải thích chi tiết về sự đổi mới trong giải pháp." },
      { code: "3.2", isCV: false, l1: "Mô hình/bản vẽ không rõ ràng thể hiện giải pháp.", l2: "Mô hình/bản vẽ đơn giản thể hiện giải pháp.", l3: "Mô hình/bản vẽ chi tiết thể hiện giải pháp." }
    ]
  },
  {
    section: "4. LẶP LẠI",
    desc: "Nhóm đã chia sẻ ý tưởng của mình với những người khác, thu thập phản hồi và đưa ra những cải tiến cho giải pháp của họ.",
    rows: [
      { code: "4.1", isCV: false, l1: "Họ chia sẻ giải pháp của mình với người khác ở mức tối thiểu.", l2: "Giải pháp đã được chia sẻ với ít nhất một người/nhóm.", l3: "Giải pháp được chia sẻ với nhiều người/nhóm." },
      { code: "4.2", isCV: false, l1: "Có rất ít bằng chứng cho thấy sự cải thiện dựa trên phản hồi.", l2: "Một phần bằng chứng về sự cải thiện dựa trên phản hồi.", l3: "Có bằng chứng rõ ràng về sự cải thiện dựa trên phản hồi." }
    ]
  },
  {
    section: "5. GIAO TIẾP",
    desc: "Nhóm đã trình bày một cách hiệu quả giải pháp của mình, tác động của nó đến những người khác và cùng nhau ăn mừng những tiến bộ đạt được.",
    rows: [
      { code: "5.1", isCV: true,  l1: "Giải thích về giải pháp và tác động tiềm năng của nó đối với người khác chưa rõ ràng.", l2: "Giải thích chưa đầy đủ về giải pháp và tác động tiềm năng của nó đối với người khác.", l3: "Giải thích rõ ràng về giải pháp và tác động tiềm năng của nó đối với người khác." },
      { code: "5.2", isCV: true,  l1: "Bài thuyết trình thể hiện sự thiếu tự hào hoặc nhiệt tình đối với công việc của họ.", l2: "Bài thuyết trình thể hiện một phần niềm tự hào hoặc sự nhiệt tình đối với công việc của họ.", l3: "Bài thuyết trình thể hiện rõ niềm tự hào hoặc sự nhiệt tình đối với công việc của họ." }
    ]
  }
];

const RD_CV_CODES = ["1.2", "2.1", "4.2", "5.1", "5.2"];
const IP_CV_CODES = ["1.2", "2.2", "3.1", "5.1", "5.2"];

// State toàn cục
let currentUser = null;        // null hoặc object trong JUDGE_ACCOUNTS
let currentView = "LANDING";   // "LANDING" | "JUDGE_RG" | "JUDGE_RUBRIC" | "RESULTS"
let selectedTeamId = 1;        // 1..8
let activeRubricTab = "RD";    // "RD" (Thiết kế Robot) | "IP" (Dự án Đổi mới)
let appData = null;

// Khởi tạo dữ liệu mặc định cho 8 nhóm
function createInitialData() {
  const defaultNames = [
    "LSTS BioGlow 01",
    "LSTS Innovators",
    "LSTS TechBot",
    "LSTS EcoGuardians",
    "LSTS Lumina",
    "LSTS CyberPulse",
    "LSTS GreenMinds",
    "LSTS Nexus"
  ];
  const teams = {};
  for (let i = 1; i <= 8; i++) {
    teams[i] = {
      id: i,
      code: `NHÓM 0${i}`,
      teamName: `Nhóm ${i} – ${defaultNames[i - 1]}`,
      robotGame: {
        completed: false,
        updatedBy: "",
        updatedAt: "",
        run1: {},
        run1TimeSec: 180,
        run2: {},
        run2TimeSec: 180
      },
      rubric: {
        completed: false,
        updatedBy: "",
        updatedAt: "",
        rdScores: {},
        rdNotes: {},
        ipScores: {},
        ipNotes: {}
      }
    };
  }
  return {
    lastModified: new Date().toISOString(),
    allowPrintAndPublish: false, // Chỉ khi Quản trị viên (Admin) bật cho phép In & Công bố thì điểm số và kết quả mới được mở
    teams
  };
}

// Mã hóa / Giải mã đối xứng dữ liệu lưu trữ cục bộ (Ngăn học sinh đọc trộm điểm hoặc URL trong LocalStorage)
function cipherTransform(str, secretSeed) {
  const keyHash = sha256Hash(`${AUTH_SALT}:${secretSeed}`);
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const k = keyHash.charCodeAt(i % keyHash.length);
    out += String.fromCharCode(str.charCodeAt(i) ^ (k & 0x7f));
  }
  return out;
}

function encodeSecureStorage(obj, seed = "STORAGE_V2") {
  try {
    const json = encodeURIComponent(JSON.stringify(obj));
    const xored = cipherTransform(json, seed);
    return "LSTS_ENC_V2:" + btoa(xored);
  } catch (e) {
    return JSON.stringify(obj);
  }
}

function decodeSecureStorage(raw, seed = "STORAGE_V2") {
  if (!raw) return null;
  if (raw.startsWith("LSTS_ENC_V2:")) {
    const b64 = raw.slice("LSTS_ENC_V2:".length);
    const xored = atob(b64);
    const json = cipherTransform(xored, seed);
    return JSON.parse(decodeURIComponent(json));
  }
  return JSON.parse(raw);
}

function cleanEmptyTeamStates(data) {
  if (!data || !data.teams) return;
  for (let i = 1; i <= 8; i++) {
    const t = data.teams[i];
    if (!t) continue;
    if (t.robotGame) {
      const r1 = calcRunScore(t.robotGame.run1);
      const r2 = calcRunScore(t.robotGame.run2);
      // Tự động gỡ trạng thái Đã cập nhật nếu điểm bằng 0 do bấm Lưu nhầm khi xóa
      if (t.robotGame.completed && r1 === 0 && r2 === 0) {
        t.robotGame.completed = false;
        t.robotGame.updatedBy = "";
        t.robotGame.updatedAt = "";
      }
    }
  }
}

function loadData() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      appData = decodeSecureStorage(raw, "SCORE_VAULT");
      if (typeof appData.allowPrintAndPublish !== "boolean") {
        appData.allowPrintAndPublish = false;
      }
      // Đảm bảo đủ 8 nhóm
      for (let i = 1; i <= 8; i++) {
        if (!appData.teams || !appData.teams[i]) {
          appData = createInitialData();
          break;
        }
      }
      cleanEmptyTeamStates(appData);
    } else {
      appData = createInitialData();
      saveData(false);
    }
  } catch (e) {
    console.error("Load data error:", e);
    appData = createInitialData();
  }
}

function saveData(triggerCloud = true) {
  appData.lastModified = new Date().toISOString();
  localStorage.setItem(STORAGE_KEY, encodeSecureStorage(appData, "SCORE_VAULT"));
  if (triggerCloud) {
    pushToCloudIfConfigured();
  }
}

function saveSessionState() {
  if (!currentUser) {
    localStorage.removeItem(SESSION_KEY);
    return;
  }
  const sessionObj = {
    currentUser,
    currentView,
    selectedTeamId,
    activeRubricTab
  };
  localStorage.setItem(SESSION_KEY, encodeSecureStorage(sessionObj, "AUTH_SESSION_VAULT"));
}

function restoreSessionState() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return;
    const sessionObj = decodeSecureStorage(raw, "AUTH_SESSION_VAULT");
    if (sessionObj && sessionObj.currentUser && sessionObj.currentUser.role) {
      currentUser = sessionObj.currentUser;
      selectedTeamId = Number(sessionObj.selectedTeamId) >= 1 && Number(sessionObj.selectedTeamId) <= 8
        ? Number(sessionObj.selectedTeamId)
        : 1;
      activeRubricTab = sessionObj.activeRubricTab === "IP" ? "IP" : "RD";
      const savedView = sessionObj.currentView || "LANDING";
      if (savedView === "JUDGE_RG" && (currentUser.role === "RG" || currentUser.role === "ADMIN")) {
        currentView = "JUDGE_RG";
      } else if (savedView === "JUDGE_RUBRIC" && (currentUser.role === "RUBRIC" || currentUser.role === "ADMIN")) {
        currentView = "JUDGE_RUBRIC";
      } else if (savedView === "RESULTS") {
        currentView = "RESULTS";
      } else {
        currentView = "LANDING";
      }
    }
  } catch (e) {
    console.warn("Restore session error:", e);
  }
}

function isResultPublishedByAdmin() {
  return Boolean(appData && appData.allowPrintAndPublish);
}

function canShowScoreDetails() {
  return Boolean((appData && appData.allowPrintAndPublish) || (currentUser && currentUser.role === "ADMIN"));
}

function toggleAdminPublishResults(forceState) {
  if (!currentUser || currentUser.role !== "ADMIN") {
    showToast("🔒 Chỉ Quản trị viên (Admin) mới có quyền cho phép In & Công bố kết quả!");
    return;
  }
  const st = getAllTeamsStatus();
  const nextState = typeof forceState === "boolean" ? forceState : !appData.allowPrintAndPublish;
  if (nextState && !st.allCompleted) {
    showToast(`⚠️ Hiện mới cập nhật đủ ${st.fullDoneCount}/8 nhóm! Cần cập nhật đủ 8/8 nhóm trước khi công bố kết quả.`);
    return;
  }
  appData.allowPrintAndPublish = nextState;
  saveData(true);
  if (nextState) {
    showToast("🔓 Quản trị viên ĐÃ CHO PHÉP IN & CÔNG BỐ KẾT QUẢ! Điểm số và Bảng xếp hạng đã được mở khóa.");
  } else {
    showToast("🔒 Quản trị viên ĐÃ KHÓA CÔNG BỐ KẾT QUẢ! Giao diện ngoài chỉ hiển thị trạng thái 'Đã cập nhật điểm'.");
    if (currentView === "RESULTS") currentView = "LANDING";
  }
  renderApp();
}

// ============================================================================
// TÍNH TOÁN ĐIỂM SỐ & THUẬT TOÁN XẾP HẠNG (TIE-BREAKER CHUẨN)
// ============================================================================

function calcRunScore(runChecks) {
  let total = 0;
  RG_CRITERIA.forEach(group => {
    group.items.forEach(item => {
      if (runChecks && runChecks[item.code]) {
        total += item.pts;
      }
    });
  });
  return total;
}

function computeTeamSummary(team) {
  // 1. Robot Game (Max 110)
  const r1Score = calcRunScore(team.robotGame.run1);
  const r2Score = calcRunScore(team.robotGame.run2);
  const t1 = Number(team.robotGame.run1TimeSec) || 240;
  const t2 = Number(team.robotGame.run2TimeSec) || 240;

  let officialRgScore = 0;
  let officialRgTimeSec = 240;
  let bestRunLabel = "Lượt 1";

  if (r1Score > r2Score) {
    officialRgScore = r1Score;
    officialRgTimeSec = t1;
    bestRunLabel = "Lượt 1";
  } else if (r2Score > r1Score) {
    officialRgScore = r2Score;
    officialRgTimeSec = t2;
    bestRunLabel = "Lượt 2";
  } else {
    // Nếu 2 lượt bằng điểm nhau, ưu tiên lấy lượt có thời gian hoàn thành nhanh hơn
    officialRgScore = r1Score;
    if (t1 <= t2) {
      officialRgTimeSec = t1;
      bestRunLabel = "Lượt 1";
    } else {
      officialRgTimeSec = t2;
      bestRunLabel = "Lượt 2";
    }
  }

  // 2. Thiết kế Robot (Max 40) & CV từ RD (Max 20)
  let rdTotal = 0;
  let rdCvTotal = 0;
  let rdCount = 0;
  RD_SECTIONS.forEach(sec => {
    sec.rows.forEach(r => {
      const val = Number(team.rubric.rdScores[r.code]) || 0;
      if (val > 0) rdCount++;
      rdTotal += val;
      if (r.isCV) rdCvTotal += val;
    });
  });

  // 3. Dự án Đổi mới (Max 40) & CV từ IP (Max 20)
  let ipTotal = 0;
  let ipCvTotal = 0;
  let ipCount = 0;
  IP_SECTIONS.forEach(sec => {
    sec.rows.forEach(r => {
      const val = Number(team.rubric.ipScores[r.code]) || 0;
      if (val > 0) ipCount++;
      ipTotal += val;
      if (r.isCV) ipCvTotal += val;
    });
  });

  const cvTotal = rdCvTotal + ipCvTotal; // Max 40
  const grandTotal = officialRgScore + rdTotal + ipTotal + cvTotal; // Max 230

  const isRgDone = Boolean(team.robotGame.completed);
  const isRubricDone = Boolean(team.rubric.completed && rdCount === 10 && ipCount === 10);
  const isFullyDone = isRgDone && isRubricDone;

  return {
    id: team.id,
    code: team.code,
    teamName: team.teamName,
    isRgDone,
    isRubricDone,
    isFullyDone,
    r1Score,
    r2Score,
    t1,
    t2,
    bestRunLabel,
    robotGameScore: officialRgScore,
    robotGameTimeSec: officialRgTimeSec,
    robotDesignScore: rdTotal,
    innovationProjectScore: ipTotal,
    coreValuesScore: cvTotal,
    rdCvTotal,
    ipCvTotal,
    totalScore: grandTotal,
    rgUpdatedBy: team.robotGame.updatedBy,
    rubricUpdatedBy: team.rubric.updatedBy
  };
}

function getAllTeamsStatus() {
  let rgDoneCount = 0;
  let rubricDoneCount = 0;
  let fullDoneCount = 0;
  const summaries = [];

  for (let i = 1; i <= 8; i++) {
    const s = computeTeamSummary(appData.teams[i]);
    if (s.isRgDone) rgDoneCount++;
    if (s.isRubricDone) rubricDoneCount++;
    if (s.isFullyDone) fullDoneCount++;
    summaries.push(s);
  }

  return {
    rgDoneCount,
    rubricDoneCount,
    fullDoneCount,
    allCompleted: fullDoneCount === 8,
    summaries
  };
}

/**
 * Sắp xếp 8 nhóm theo đúng thứ tự ưu tiên:
 * 1. Tổng điểm cao hơn (totalScore DESC)
 * 2. Điểm Robot Game cao hơn (robotGameScore DESC)
 * 3. Điểm Thiết Kế Robot cao hơn (robotDesignScore DESC)
 * 4. Điểm Giá Trị Cốt Lõi cao hơn (coreValuesScore DESC)
 * 5. Thời gian hoàn thành Robot Game nhanh hơn (robotGameTimeSec ASC)
 */
function getRankedTeams() {
  const { summaries } = getAllTeamsStatus();
  const sorted = [...summaries].sort((a, b) => {
    if (b.totalScore !== a.totalScore) return b.totalScore - a.totalScore;
    if (b.robotGameScore !== a.robotGameScore) return b.robotGameScore - a.robotGameScore;
    if (b.robotDesignScore !== a.robotDesignScore) return b.robotDesignScore - a.robotDesignScore;
    if (b.coreValuesScore !== a.coreValuesScore) return b.coreValuesScore - a.coreValuesScore;
    if (a.robotGameTimeSec !== b.robotGameTimeSec) return a.robotGameTimeSec - b.robotGameTimeSec;
    return a.id - b.id;
  });

  // Gán thứ hạng & giải thích lý do thắng Tie-breaker nếu có đồng điểm
  sorted.forEach((item, idx) => {
    item.rank = idx + 1;
    item.isQualified = item.rank <= 4;
    item.tieBreakReason = "";

    // Kiểm tra với đội ngay sau hoặc ngay trước nếu bằng Tổng điểm
    const prev = idx > 0 ? sorted[idx - 1] : null;
    const next = idx < sorted.length - 1 ? sorted[idx + 1] : null;

    if (next && next.totalScore === item.totalScore) {
      if (item.robotGameScore > next.robotGameScore) {
        item.tieBreakReason = `Thắng Tie-break #1 (Đồng ${item.totalScore}đ): Điểm Robot Game cao hơn (${item.robotGameScore}đ > ${next.robotGameScore}đ)`;
      } else if (item.robotDesignScore > next.robotDesignScore) {
        item.tieBreakReason = `Thắng Tie-break #2 (Đồng ${item.totalScore}đ & RG): Điểm Robot Design cao hơn (${item.robotDesignScore}đ > ${next.robotDesignScore}đ)`;
      } else if (item.coreValuesScore > next.coreValuesScore) {
        item.tieBreakReason = `Thắng Tie-break #3 (Đồng ${item.totalScore}đ, RG & RD): Điểm Core Values cao hơn (${item.coreValuesScore}đ > ${next.coreValuesScore}đ)`;
      } else if (item.robotGameTimeSec < next.robotGameTimeSec) {
        item.tieBreakReason = `Thắng Tie-break #4 (Đồng ${item.totalScore}đ & các điểm thành phần): Thời gian Robot Game nhanh hơn (${formatSeconds(item.robotGameTimeSec)} < ${formatSeconds(next.robotGameTimeSec)})`;
      }
    } else if (prev && prev.totalScore === item.totalScore && !item.tieBreakReason) {
      if (prev.robotGameScore > item.robotGameScore) {
        item.tieBreakReason = `Xếp sau Tie-break #1 (Đồng ${item.totalScore}đ): Kém điểm Robot Game (${item.robotGameScore}đ < ${prev.robotGameScore}đ)`;
      } else if (prev.robotDesignScore > item.robotDesignScore) {
        item.tieBreakReason = `Xếp sau Tie-break #2 (Đồng ${item.totalScore}đ): Kém điểm Robot Design (${item.robotDesignScore}đ < ${prev.robotDesignScore}đ)`;
      } else if (prev.coreValuesScore > item.coreValuesScore) {
        item.tieBreakReason = `Xếp sau Tie-break #3 (Đồng ${item.totalScore}đ): Kém điểm Core Values (${item.coreValuesScore}đ < ${prev.coreValuesScore}đ)`;
      } else if (prev.robotGameTimeSec < item.robotGameTimeSec) {
        item.tieBreakReason = `Xếp sau Tie-break #4 (Đồng ${item.totalScore}đ): Thời gian Robot Game chậm hơn (${formatSeconds(item.robotGameTimeSec)} > ${formatSeconds(prev.robotGameTimeSec)})`;
      }
    }
  });

  return sorted;
}

function formatSeconds(sec) {
  const s = Math.max(0, Math.round(Number(sec) || 0));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${String(m).padStart(2, "0")}:${String(rem).padStart(2, "0")} (${s}s)`;
}

// ============================================================================
// ĐĂNG NHẬP, ĐIỀU HƯỚNG & THÔNG BÁO
// ============================================================================

function showToast(msg) {
  const el = document.getElementById("toastBox");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => {
    el.classList.remove("show");
  }, 3200);
}

async function handleLogin(e) {
  if (e) e.preventDefault();
  const u = (document.getElementById("loginUser")?.value || "").trim().toUpperCase();
  const p = (document.getElementById("loginPass")?.value || "").trim();
  const urlFromLogin = (document.getElementById("loginCloudUrl")?.value || "").trim();

  if (urlFromLogin) {
    const curCfg = getCloudCfg();
    localStorage.setItem(CLOUD_CFG_KEY, encodeSecureStorage({ ...curCfg, url: urlFromLogin }, "EXCEL_CLOUD_CFG"));
  }

  // Tính toán mã băm kéo giãn 20.000 vòng (Key Stretching / PBKDF2-SHA256)
  const uHash = stretchHash(`USR:${u}`);
  const pHash = stretchHash(`PWD:${u}:${p}`);

  const cfg = getCloudCfg();
  let verifiedRole = null;

  // 1. Ưu tiên xác thực trực tiếp trên Backend Google Apps Script (doPost) nếu đã kết nối URL
  if (cfg.url && cfg.url.includes("script.google.com")) {
    try {
      showToast("🔐 Đang xác thực tài khoản và phân quyền trên Google Cloud...");
      const res = await fetch(cfg.url, {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({
          action: "VERIFY_LOGIN",
          uHash,
          pHash
        })
      });
      const json = await res.json();
      if (json && json.ok && json.role) {
        verifiedRole = json.role;
        if (json.appData && json.appData.teams) {
          appData = json.appData;
          saveData(false);
        }
      } else if (json && json.error === "INVALID_CREDENTIALS") {
        showToast("⚠️ Tài khoản hoặc mật khẩu không chính xác (Từ chối bởi Google Cloud Server)!");
        return;
      }
    } catch (err) {
      console.warn("Cloud login fallback:", err);
    }
  }

  // 2. Dự phòng xác thực qua bảng mã băm 20.000 vòng (nếu chưa cấu hình URL hoặc mất kết nối)
  if (!verifiedRole) {
    const rec = OFFLINE_AUTH_RECORDS.find(r => r.userHash === uHash && r.passHash === pHash);
    if (!rec) {
      showToast("⚠️ Thông tin tài khoản hoặc mật khẩu không chính xác!");
      return;
    }
    verifiedRole = rec.role;
  }

  const roleLabels = {
    RG: "Giám khảo Hạng mục Robot Game",
    RUBRIC: "Giám khảo Thiết kế Robot & Dự án Đổi mới",
    ADMIN: "Quản trị viên Hệ thống (Ban Tổ Chức)"
  };

  // Lưu uHash & pHash chỉ trong bộ nhớ RAM (biến currentUser), tuyệt đối không ghi xuống đĩa
  currentUser = {
    id: verifiedRole === "ADMIN" ? "Quản trị viên" : u,
    name: roleLabels[verifiedRole] || "Thành viên Ban Giám khảo",
    role: verifiedRole,
    uHash,
    pHash
  };

  if (currentUser.role === "RG") {
    currentView = "JUDGE_RG";
    showToast(`✅ Đăng nhập thành công! Đã mở màn hình nhập điểm Robot Game.`);
  } else if (currentUser.role === "RUBRIC") {
    currentView = "JUDGE_RUBRIC";
    showToast(`✅ Đăng nhập thành công! Đã mở màn hình chấm Thiết Kế Robot & Dự Án Đổi Mới.`);
  } else if (currentUser.role === "ADMIN") {
    currentView = "JUDGE_RG";
    showToast(`✅ Xin chào Quản trị viên! Bạn có toàn quyền quản lý hệ thống.`);
  }
  saveSessionState();
  renderApp();
}

function handleLogout(wipeStorage = false) {
  currentUser = null;
  currentView = "LANDING";
  localStorage.removeItem(SESSION_KEY);
  if (wipeStorage) {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.clear();
    appData = createInitialData();
    showToast("🧹 Đã đăng xuất và xóa sạch toàn bộ dữ liệu tạm trên trình duyệt này!");
  } else {
    showToast("Đã đăng xuất khỏi hệ thống.");
  }
  renderApp();
}

function wipeBrowserTraceAndLogout() {
  if (!confirm("An toàn vận hành phòng thi:\nBạn có muốn ĐĂNG XUẤT và XÓA SẠCH toàn bộ dữ liệu lưu tạm (localStorage) trên trình duyệt của máy tính này không?\n(Dữ liệu đã đồng bộ lên File Excel Trực Tuyến vẫn được giữ nguyên an toàn trên Google Cloud)")) {
    return;
  }
  handleLogout(true);
}

function navigateTo(view) {
  if (view === "JUDGE_RG") {
    if (!currentUser || (currentUser.role !== "RG" && currentUser.role !== "ADMIN")) {
      showToast("🔒 Vui lòng đăng nhập tài khoản Giám khảo được phân công để truy cập!");
      currentView = "LANDING";
      saveSessionState();
      renderApp();
      return;
    }
  }
  if (view === "JUDGE_RUBRIC") {
    if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) {
      showToast("🔒 Vui lòng đăng nhập tài khoản Giám khảo được phân công để truy cập!");
      currentView = "LANDING";
      saveSessionState();
      renderApp();
      return;
    }
  }
  if (view === "RESULTS") {
    const st = getAllTeamsStatus();
    if (!st.allCompleted) {
      showToast("🔒 Chưa thể mở bảng kết quả! Cần cập nhật đầy đủ điểm cho cả 8 nhóm.");
      return;
    }
    if (!isResultPublishedByAdmin() && (!currentUser || currentUser.role !== "ADMIN")) {
      showToast("🔒 Đã cập nhật điểm 8/8 nhóm, nhưng chỉ khi Quản trị viên (Admin) cho phép In & Công bố thì kết quả mới được hiển thị!");
      return;
    }
  }
  currentView = view;
  saveSessionState();
  window.scrollTo({ top: 0, behavior: "smooth" });
  renderApp();
}

// ============================================================================
// RENDER GIAO DIỆN CHÍNH
// ============================================================================

function renderApp() {
  renderNavbar();
  const main = document.getElementById("appMain");
  if (!main) return;

  if (currentView === "LANDING") {
    main.innerHTML = renderLandingView();
  } else if (currentView === "JUDGE_RG") {
    main.innerHTML = renderJudgeRgView();
  } else if (currentView === "JUDGE_RUBRIC") {
    main.innerHTML = renderJudgeRubricView();
  } else if (currentView === "RESULTS") {
    main.innerHTML = renderResultsView();
  }
}

function renderNavbar() {
  const navActions = document.getElementById("navActions");
  if (!navActions) return;

  const st = getAllTeamsStatus();
  const isPublished = isResultPublishedByAdmin();
  const canOpenResults = st.allCompleted && (isPublished || (currentUser && currentUser.role === "ADMIN"));

  let html = `
    <button class="btn btn-outline-light" onclick="navigateTo('LANDING')">
      🏠 Trang chủ
    </button>
  `;

  if (currentUser) {
    if (currentUser.role === "ADMIN") {
      html += `
        <button class="btn ${currentView === 'JUDGE_RG' ? 'btn-primary' : 'btn-outline-light'}" onclick="navigateTo('JUDGE_RG')">
          🤖 Robot Game
        </button>
        <button class="btn ${currentView === 'JUDGE_RUBRIC' ? 'btn-primary' : 'btn-outline-light'}" onclick="navigateTo('JUDGE_RUBRIC')">
          ⚙️💡 TK Robot & Dự án
        </button>
      `;
    } else {
      const targetView = currentUser.role === "RG" ? "JUDGE_RG" : "JUDGE_RUBRIC";
      html += `
        <button class="btn btn-primary" onclick="navigateTo('${targetView}')">
          📝 Chấm điểm
        </button>
      `;
    }
  }

  let resultBtnLabel = `Kết quả (${st.fullDoneCount}/8)`;
  if (st.allCompleted) {
    if (isPublished) {
      resultBtnLabel = "Kết quả chính thức";
    } else if (currentUser && currentUser.role === "ADMIN") {
      resultBtnLabel = "Duyệt kết quả";
    } else {
      resultBtnLabel = "Chờ công bố";
    }
  }

  html += `
    <button class="btn btn-gold" ${canOpenResults ? "" : "disabled"} onclick="navigateTo('RESULTS')" title="${canOpenResults ? 'Xem kết quả chính thức' : 'Kết quả chỉ hiển thị khi đủ điểm 8 nhóm và được công bố'}">
      🏆 ${resultBtnLabel}
    </button>
  `;

  if (currentUser) {
    html += `
      <button class="btn btn-outline-light" onclick="handleLogout()">
        Đăng xuất
      </button>
    `;
  }

  navActions.innerHTML = html;
}

// ============================================================================
// TRANG 1: GIỚI THIỆU MÙA GIẢI, LUẬT THI, CỔNG KẾT QUẢ & ĐĂNG NHẬP GIÁM KHẢO
// ============================================================================

let activeRuleTab = "RG"; // "RG" | "RD" | "IP" | "TIE"

function switchRuleTab(tab) {
  activeRuleTab = tab;
  renderApp();
}

function renderLandingView() {
  const st = getAllTeamsStatus();
  const isPublished = isResultPublishedByAdmin();
  const isAdmin = currentUser && currentUser.role === "ADMIN";
  const canOpenResults = st.allCompleted && (isPublished || isAdmin);

  const dotsHtml = st.summaries.map(s => {
    let cls = "";
    let tip = `${s.code}: Chưa cập nhật điểm`;
    if (s.isFullyDone) {
      cls = "complete";
      tip = `${s.code}: Đã cập nhật điểm đầy đủ`;
    } else if (s.isRgDone || s.isRubricDone) {
      cls = "partial";
      tip = `${s.code}: Đã cập nhật 1 phần (RG: ${s.isRgDone ? 'Đã cập nhật' : 'Chờ'}, Thuyết trình: ${s.isRubricDone ? 'Đã cập nhật' : 'Chờ'})`;
    }
    return `<div class="team-dot ${cls}" title="${tip}">N${s.id} ${s.isFullyDone ? "✓" : ""}</div>`;
  }).join("");

  return `
    <!-- HERO BANNER -->
    <section class="hero-banner">
      <div>
        <div class="hero-eyebrow">
          <span>🌱 TRƯỜNG THCS & THPT ĐINH THIỆN LÝ (LSTS)</span>
          <span>•</span>
          <span>MÙA GIẢI BIOGLOW</span>
        </div>
        <h2>VÒNG 3 TUYỂN CHỌN ĐỘI FLL CẤP TRƯỜNG</h2>
        <p>
          Hệ thống quản lý chấm điểm, tổng hợp và công bố kết quả chính thức dành cho 08 nhóm dự thi.
          Đánh giá toàn diện 04 trụ cột chuẩn <strong>FIRST® LEGO® League Challenge</strong> để lựa chọn
          <strong>04 Nhóm xuất sắc nhất</strong> đại diện nhà trường.
        </p>
        <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; padding: 12px 14px; background: rgba(255, 255, 255, 0.12); border: 1px solid rgba(255, 255, 255, 0.28); border-radius: 10px;">
          <div style="display: flex; align-items: center; gap: 6px; font-size: 13.5px; color: #FFFFFF;">
            <span>🕒 <strong>Thời gian thi đấu:</strong></span>
            <span style="background: #F59E0B; color: #0F172A; font-weight: 800; padding: 2px 9px; border-radius: 6px;">11h45 – 13h15 | Ngày 30/10</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px; font-size: 13.5px; color: #FFFFFF;">
            <span>🤖 <strong>Robot Game:</strong></span>
            <span style="background: rgba(16, 185, 129, 0.25); border: 1px solid #34D399; color: #A7F3D0; font-weight: 800; padding: 2px 9px; border-radius: 6px;">📍 Phòng A211</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px; font-size: 13.5px; color: #FFFFFF;">
            <span>⚙️💡 <strong>Thiết Kế Robot & Dự Án Đổi Mới:</strong></span>
            <span style="background: rgba(59, 130, 246, 0.28); border: 1px solid #93C5FD; color: #DBEAFE; font-weight: 800; padding: 2px 9px; border-radius: 6px;">📍 Phòng B217</span>
          </div>
        </div>
        <div class="hero-Formula-pills">
          <div class="formula-pill">🤖 Robot Game: <strong>110đ</strong></div>
          <div class="formula-pill">⚙️ Thiết Kế Robot: <strong>40đ</strong></div>
          <div class="formula-pill">💡 Dự Án Đổi Mới: <strong>40đ</strong></div>
          <div class="formula-pill">❤️ Giá Trị Cốt Lõi: <strong>40đ</strong></div>
          <div class="formula-pill">∑ Tổng Điểm Toàn Diện: <strong>230đ</strong></div>
        </div>
      </div>

      <!-- CỔNG CÔNG BỐ KẾT QUẢ (CHỈ MỞ KHI ĐỦ ĐIỂM 8 NHÓM VÀ ADMIN CHO PHÉP IN & CÔNG BỐ) -->
      <div class="result-gate-card">
        <div class="result-gate-header">
          <h3>🏆 CỔNG KẾT QUẢ THI ĐẤU</h3>
          <span class="status-badge ${(st.allCompleted && isPublished) ? "status-ready" : "status-locked"}">
            ${(st.allCompleted && isPublished)
              ? "✅ ĐÃ CHO PHÉP IN & CÔNG BỐ"
              : (st.allCompleted ? "✅ ĐÃ CẬP NHẬT ĐIỂM 8/8 NHÓM" : "⏳ ĐANG CẬP NHẬT ĐIỂM")}
          </span>
        </div>
        <p style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 10px;">
          Thông tin điểm số và kết quả chính thức <strong>chỉ được hiển thị khi Quản trị viên cho phép in & công bố kết quả</strong>. Trước thời điểm đó, hệ thống chỉ thông báo trạng thái đã cập nhật điểm của từng nhóm.
        </p>

        <div class="progress-grid">
          <div class="progress-item">
            <div class="lbl">Robot Game (A211)</div>
            <div class="val" style="font-size: 14px;">Đã cập nhật: ${st.rgDoneCount}/8</div>
          </div>
          <div class="progress-item">
            <div class="lbl">TK Robot & Dự Án (B217)</div>
            <div class="val" style="font-size: 14px;">Đã cập nhật: ${st.rubricDoneCount}/8</div>
          </div>
        </div>

        <div class="team-dots-bar">
          ${dotsHtml}
        </div>

        <button
          class="btn ${(st.allCompleted && isPublished) ? "btn-gold" : "btn-navy"} btn-result-main"
          ${canOpenResults ? "" : "disabled"}
          onclick="navigateTo('RESULTS')"
        >
          ${(st.allCompleted && isPublished)
            ? "🏆 Xem kết quả chính thức"
            : (st.allCompleted
              ? (isAdmin ? "🔓 Xem & Công bố kết quả" : "🔒 Chờ công bố kết quả (Đã cập nhật 8/8 nhóm)")
              : `⏳ Đang cập nhật điểm (${st.fullDoneCount}/8 nhóm)`)}
        </button>

        ${isAdmin ? `
          <div style="margin-top: 10px;">
            <button
              class="btn ${isPublished ? "btn-danger" : "btn-primary"}"
              style="width: 100%; font-size: 12.5px; padding: 8px 12px;"
              onclick="toggleAdminPublishResults()"
            >
              ${isPublished ? "🔒 Khóa công bố kết quả" : "🔓 Công bố kết quả"}
            </button>
          </div>
        ` : ""}
      </div>
    </section>

    <!-- MAIN GRID: BÊN TRÁI LUẬT THI & BIỂU MẪU, BÊN PHẢI ĐĂNG NHẬP GIÁM KHẢO -->
    <div class="landing-grid">
      <div>
        <!-- KHỐI TỔNG QUAN NỘI DUNG THI THUYẾT TRÌNH & QUY TRÌNH ROBOT GAME -->
        <div class="card">
          <div class="card-header" style="flex-wrap: wrap; gap: 8px;">
            <h3>📌 Nội Dung Thi Đấu Chính Thức & Yêu Cầu Trình Bày (Mùa Giải BIOGLOW)</h3>
            <span class="status-badge status-ready" style="font-size: 12px;">🗓️ 11h45 – 13h15 | Ngày 30/10</span>
          </div>

          <!-- BẢNG TÓM TẮT THỜI GIAN & PHÒNG THI -->
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px;">
            <div style="background: #FFFBEB; border: 1px solid #FDE68A; border-left: 4px solid #D97706; border-radius: 8px; padding: 10px 14px;">
              <div style="font-size: 11.5px; font-weight: 700; color: #92400E; text-transform: uppercase;">🕒 Thời Gian Tổ Chức</div>
              <div style="font-size: 14px; font-weight: 800; color: #78350F; margin-top: 2px;">11h45 đến 13h15</div>
              <div style="font-size: 12.5px; color: #B45309; font-weight: 600;">Ngày 30 tháng 10</div>
            </div>
            <div style="background: #ECFDF5; border: 1px solid #A7F3D0; border-left: 4px solid #059669; border-radius: 8px; padding: 10px 14px;">
              <div style="font-size: 11.5px; font-weight: 700; color: #065F46; text-transform: uppercase;">🤖 Phần Thi Robot Game</div>
              <div style="font-size: 15px; font-weight: 800; color: #047857; margin-top: 2px;">📍 Phòng A211</div>
              <div style="font-size: 12px; color: #065F46;">Thi đấu trên sa bàn (2 lượt chạy)</div>
            </div>
            <div style="background: #EFF6FF; border: 1px solid #BFDBFE; border-left: 4px solid #1D4ED8; border-radius: 8px; padding: 10px 14px;">
              <div style="font-size: 11.5px; font-weight: 700; color: #1E40AF; text-transform: uppercase;">⚙️💡 Thiết Kế Robot & Dự Án Đổi Mới</div>
              <div style="font-size: 15px; font-weight: 800; color: #1D4ED8; margin-top: 2px;">📍 Phòng B217</div>
              <div style="font-size: 12px; color: #1E40AF;">Thuyết trình & Phản biện cùng BGK</div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
            <!-- PHẦN 1: ROBOT DESIGN -->
            <div style="background: var(--rd-light); border: 1px solid #BFDBFE; border-left: 5px solid var(--rd-primary); border-radius: 8px; padding: 16px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px;">
                <span style="font-weight: 800; color: var(--rd-primary); font-size: 14.5px;">⚙️ Phần 1: ROBOT DESIGN (40 ĐIỂM)</span>
                <div style="display: flex; gap: 6px;">
                  <span class="badge-code" style="background: #DBEAFE; color: #1E40AF;">📍 Phòng B217</span>
                  <span class="badge-code" style="background: #fff;">⏱️ Trình bày: 02 phút</span>
                </div>
              </div>
              <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 8px;">
                Trong vòng <strong>02 phút</strong>, đội thi giới thiệu trước Ban Giám khảo các nội dung trọng tâm:
              </p>
              <ul style="font-size: 13px; color: var(--text-primary); margin-left: 18px; line-height: 1.65;">
                <li><strong>Cấu trúc robot</strong> (Thiết kế khung gầm, truyền động, độ ổn định)</li>
                <li><strong>Cảm biến sử dụng</strong> (Loại cảm biến, vị trí lắp đặt và mục đích)</li>
                <li><strong>Cơ chế thực hiện nhiệm vụ</strong> (Tay gắp, cơ cấu nâng/móc, đẩy vật thể)</li>
                <li><strong>Chương trình điều khiển</strong> (Thuật toán dò line tự động, điều hướng)</li>
              </ul>
            </div>

            <!-- PHẦN 2: DỰ ÁN ĐỔI MỚI -->
            <div style="background: var(--ip-light); border: 1px solid #99F6E4; border-left: 5px solid var(--ip-primary); border-radius: 8px; padding: 16px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px;">
                <span style="font-weight: 800; color: var(--ip-primary); font-size: 14.5px;">💡 Phần 2: DỰ ÁN ĐỔI MỚI (40 ĐIỂM)</span>
                <div style="display: flex; gap: 6px;">
                  <span class="badge-code" style="background: #CCFBF1; color: #0F766E;">📍 Phòng B217</span>
                  <span class="badge-code" style="background: #fff; color: var(--ip-primary);">⏱️ Trình bày: 02 phút</span>
                </div>
              </div>
              <p style="font-size: 12.8px; color: var(--text-secondary); margin-bottom: 6px;">
                <strong>Chủ đề chuẩn bị (Đa dạng sinh học – BIOGLOW):</strong>
              </p>
              <ul style="font-size: 12.5px; color: var(--text-primary); margin-left: 18px; margin-bottom: 10px; line-height: 1.55;">
                <li>Bảo tồn đa dạng sinh học & Bảo vệ động thực vật.</li>
                <li>Cải thiện môi trường sống của sinh vật.</li>
                <li>Giảm tác động tiêu cực của con người đến hệ sinh thái.</li>
                <li>Ứng dụng công nghệ để theo dõi, bảo vệ hoặc phục hồi hệ sinh thái.</li>
                <li>Xây dựng trường học hoặc cộng đồng thân thiện với thiên nhiên.</li>
              </ul>
              <div style="background: #FFFFFF; border: 1px solid #99F6E4; border-radius: 6px; padding: 10px 12px;">
                <div style="font-size: 12.5px; font-weight: 800; color: var(--ip-primary); margin-bottom: 4px;">
                  🎯 Sản phẩm trình bày (Trong 2 phút cần trả lời 4 câu hỏi):
                </div>
                <ol style="font-size: 12.5px; color: var(--text-primary); margin-left: 18px; line-height: 1.55;">
                  <li>Vấn đề về đa dạng sinh học mà đội quan tâm là gì?</li>
                  <li>Tại sao vấn đề đó quan trọng?</li>
                  <li>Giải pháp của đội là gì?</li>
                  <li>Giải pháp mang lại lợi ích gì?</li>
                </ol>
              </div>
            </div>
          </div>

          <!-- QUY TRÌNH ROBOT GAME & CÁCH TÍNH CORE VALUES -->
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
            <div style="background: #F8FAFC; border: 1px solid var(--border-strong); border-left: 5px solid var(--navy-800); border-radius: 8px; padding: 15px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px;">
                <span style="font-weight: 800; color: var(--navy-800); font-size: 14px;">
                  🤖 Quy Trình & Cơ Cấu Điểm Robot Game (Tối đa 110 Điểm)
                </span>
                <span class="badge-code" style="background: #DCFCE7; color: #065F46;">📍 Phòng A211</span>
              </div>
              <div style="background: #FFFFFF; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 9px 12px; margin-bottom: 8px; font-size: 12.5px;">
                <div style="font-weight: 800; color: var(--navy-800); margin-bottom: 4px;">
                  📊 Công thức: Điểm Robot Game (110 điểm) = Điểm Nhiệm Vụ (100 điểm) + Điểm Thưởng (10 điểm)
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 4px 12px; color: var(--text-secondary);">
                  <div>• <strong>Nhiệm vụ 1:</strong> 20 điểm</div>
                  <div>• <strong>Nhiệm vụ 2:</strong> 30 điểm</div>
                  <div>• <strong>Nhiệm vụ 3:</strong> 50 điểm</div>
                  <div>• <strong>Excellence Bonus:</strong> +10 điểm <em>(5đ + 5đ)</em></div>
                </div>
              </div>
              <ul style="font-size: 12.6px; color: var(--text-secondary); margin-left: 18px; line-height: 1.55;">
                <li><strong>Lượt chạy & Thời gian:</strong> Mỗi đội có <strong>02 lượt chạy</strong>, tối đa <strong>04 phút</strong>. Robot xuất phát hoàn toàn trong khu vực <code>HOME</code>.</li>
                <li><strong>Nguyên tắc ghi điểm:</strong> Chỉ ghi nhận theo <strong>trạng thái cuối cùng</strong> của vật thể và robot. Điểm chính thức là <strong>điểm cao nhất trong 2 lượt</strong>.</li>
                <li><strong>Khiếu nại:</strong> Trong vòng <strong>03 phút</strong> từ khi công bố điểm (chỉ xử lý sai sót ghi điểm hoặc xác định trạng thái nhiệm vụ).</li>
              </ul>
            </div>

            <div style="background: var(--cv-light); border: 1px solid #FECACA; border-left: 5px solid var(--cv-primary); border-radius: 8px; padding: 15px;">
              <div style="font-weight: 800; color: var(--cv-primary); font-size: 14px; margin-bottom: 6px;">
                ⚙♥ Cách Tính Điểm Giá Trị Cốt Lõi – Core Values (Tối đa 40 Điểm)
              </div>
              <p style="font-size: 12.6px; color: var(--text-secondary); margin-bottom: 8px;">
                Điểm <strong>Core Values (40 điểm)</strong> được trích xuất và cộng tự động từ các tiêu chí có biểu tượng <span class="badge-cv">⚙♥ CV</span> trên 02 phiếu chấm thuyết trình:
              </p>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div style="background: #FFFFFF; border: 1px solid #FECACA; border-radius: 6px; padding: 8px 10px; font-size: 12.2px;">
                  <div style="font-weight: 800; color: var(--rd-primary); margin-bottom: 4px;">
                    1. Từ Phiếu Thiết Kế Robot (20 điểm):
                  </div>
                  <div style="line-height: 1.65; color: var(--text-primary);">
                    • Tiêu chí <code>1.2</code>: Tài nguyên xây dựng/lập trình<br/>
                    • Tiêu chí <code>2.1</code>: Thành viên đóng góp ý tưởng<br/>
                    • Tiêu chí <code>4.2</code>: Cải thiện qua thử nghiệm<br/>
                    • Tiêu chí <code>5.1</code>: Chia sẻ quy trình & bài học<br/>
                    • Tiêu chí <code>5.2</code>: Niềm tự hào & sự nhiệt tình
                  </div>
                </div>
                <div style="background: #FFFFFF; border: 1px solid #FECACA; border-radius: 6px; padding: 8px 10px; font-size: 12.2px;">
                  <div style="font-weight: 800; color: var(--ip-primary); margin-bottom: 4px;">
                    2. Từ Phiếu Dự Án Đổi Mới (20 điểm):
                  </div>
                  <div style="line-height: 1.65; color: var(--text-primary);">
                    • Tiêu chí <code>1.2</code>: Bằng chứng nguồn nghiên cứu<br/>
                    • Tiêu chí <code>2.2</code>: Sự tham gia của toàn đội<br/>
                    • Tiêu chí <code>3.1</code>: Giải thích sự đổi mới<br/>
                    • Tiêu chí <code>5.1</code>: Giải pháp & tác động cộng đồng<br/>
                    • Tiêu chí <code>5.2</code>: Niềm tự hào & sự nhiệt tình
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3>📘 Chi Tiết Biểu Mẫu Chấm Điểm & Quy Tắc Xử Lý Đồng Điểm</h3>
          </div>

          <div class="rule-tabs">
            <button class="rule-tab ${activeRuleTab === "RG" ? "active" : ""}" onclick="switchRuleTab('RG')">
              1. Biểu Mẫu Robot Game (110đ)
            </button>
            <button class="rule-tab ${activeRuleTab === "RD" ? "active" : ""}" onclick="switchRuleTab('RD')">
              2. Biểu Mẫu Thiết Kế Robot (40đ)
            </button>
            <button class="rule-tab ${activeRuleTab === "IP" ? "active" : ""}" onclick="switchRuleTab('IP')">
              3. Biểu Mẫu Dự Án Đổi Mới (40đ)
            </button>
            <button class="rule-tab ${activeRuleTab === "TIE" ? "active" : ""}" onclick="switchRuleTab('TIE')">
              4. Ma Trận Core Values & Tie-Breaker
            </button>
          </div>

          ${renderRuleTabContent()}
        </div>
      </div>

      <!-- CỘT PHẢI: ĐĂNG NHẬP GIÁM KHẢO & QUẢN TRỊ VIÊN -->
      <div>
        <div class="login-card">
          <div class="card-header" style="margin-bottom: 14px; padding-bottom: 10px;">
            <h3>🔐 Đăng Nhập Ban Giám Khảo</h3>
          </div>

          ${currentUser ? `
            <div style="background: var(--emerald-100); border: 1px solid #6EE7B7; padding: 14px; border-radius: 8px; margin-bottom: 16px;">
              <div style="font-weight: 800; color: #065F46; font-size: 14px;">Đang đăng nhập: ${currentUser.id}</div>
              <div style="font-size: 12.5px; color: #047857; margin-top: 4px;">${currentUser.name}</div>
            </div>
            ${currentUser.role === "ADMIN" ? `
              <button class="btn btn-primary" style="width: 100%; margin-bottom: 8px;" onclick="navigateTo('JUDGE_RG')">
                🤖 Chấm điểm Robot Game
              </button>
              <button class="btn btn-navy" style="width: 100%; margin-bottom: 10px;" onclick="navigateTo('JUDGE_RUBRIC')">
                ⚙️💡 Chấm Thiết kế Robot & Dự án
              </button>
            ` : `
              <button class="btn btn-primary" style="width: 100%; margin-bottom: 10px;" onclick="navigateTo('${currentUser.role === "RG" ? "JUDGE_RG" : "JUDGE_RUBRIC"}')">
                📝 Vào chấm điểm
              </button>
            `}
            <button class="btn btn-outline" style="width: 100%;" onclick="handleLogout(false)">
              Đăng xuất
            </button>
          ` : `
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">
              Dành cho Ban Giám khảo và Quản trị viên Trường THCS & THPT Đinh Thiện Lý.
            </p>
            <form onsubmit="handleLogin(event)" autocomplete="off">
              <div class="form-group">
                <label for="loginUser">Tài khoản</label>
                <input id="loginUser" type="text" class="form-control mono-num" placeholder="Nhập tài khoản..." required />
              </div>
              <div class="form-group">
                <label for="loginPass">Mật khẩu</label>
                <input id="loginPass" type="password" class="form-control mono-num" placeholder="Nhập mật khẩu..." required />
              </div>
              <button type="submit" class="btn btn-navy" style="width: 100%; padding: 11px;">
                Đăng nhập
              </button>
            </form>
          `}
        </div>

        <!-- THÔNG TIN TỔNG QUAN 8 ĐỘI (CHỈ HIỂN THỊ ĐÃ CẬP NHẬT ĐIỂM) -->
        <div class="card" style="margin-top: 20px;">
          <div class="card-header" style="margin-bottom: 12px; padding-bottom: 10px;">
            <h3>📋 Trạng Thái Cập Nhật Điểm 08 Nhóm</h3>
          </div>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
            Hệ thống bảo mật điểm số trong suốt quá trình chấm thi và chỉ hiển thị trạng thái đã cập nhật điểm cho đến khi Quản trị viên cho phép in & công bố kết quả.
          </p>
          <table class="data-table" style="font-size: 12.5px;">
            <thead>
              <tr>
                <th>Nhóm</th>
                <th>Robot Game (A211)</th>
                <th>TK Robot & Dự Án (B217)</th>
              </tr>
            </thead>
            <tbody>
              ${st.summaries.map(s => `
                <tr>
                  <td><strong>${s.code}</strong></td>
                  <td>
                    ${s.isRgDone
                      ? `<span style="color: var(--emerald-600); font-weight: 700;">✓ Đã cập nhật điểm</span>`
                      : `<span style="color: var(--text-muted);">⏳ Chưa cập nhật</span>`}
                  </td>
                  <td>
                    ${s.isRubricDone
                      ? `<span style="color: var(--emerald-600); font-weight: 700;">✓ Đã cập nhật điểm</span>`
                      : `<span style="color: var(--text-muted);">⏳ Chưa cập nhật</span>`}
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function renderRuleTabContent() {
  if (activeRuleTab === "RG") {
    return `
      <div>
        <div style="background: var(--bg-elevated); border: 1px solid var(--border-subtle); border-left: 4px solid var(--navy-800); border-radius: 8px; padding: 12px 16px; margin-bottom: 14px;">
          <div style="font-weight: 800; color: var(--navy-800); font-size: 14px; margin-bottom: 6px;">
            📌 Tổng quan Sa bàn & Quy định Robot Game (Tối đa 110 điểm):
          </div>
          <ul style="font-size: 13px; color: var(--text-secondary); margin-left: 18px; line-height: 1.7;">
            <li><strong>Các khu vực chức năng (07 khu vực):</strong> <code>HOME</code>, <code>Mission 1</code>, <code>Mission 2</code>, <code>Mission 3</code>, <code>GOAL 1</code>, <code>GOAL 2</code> và <code>GOAL 3</code>.</li>
            <li><strong>Quy định xuất phát:</strong> Robot bắt buộc đặt và xuất phát hoàn toàn trong khu vực <code>HOME</code>.</li>
            <li><strong>Nguyên tắc ghi nhận điểm:</strong> Điểm chỉ được ghi nhận theo <strong>trạng thái cuối cùng</strong> của vật thể và robot khi kết thúc lượt chạy.</li>
            <li><strong>Số lượt & Thời gian thi đấu:</strong> Mỗi đội có <strong>02 lượt chạy</strong> (tổng thời gian tối đa <strong>04 phút</strong>); điểm chính thức là <strong>điểm cao nhất trong 2 lượt</strong>.</li>
            <li><strong>Quy định khiếu nại:</strong> Khiếu nại trong vòng <strong>03 phút</strong> kể từ khi trọng tài công bố điểm (chỉ xử lý sai sót ghi điểm hoặc xác định trạng thái nhiệm vụ).</li>
          </ul>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 75px;">Mã</th>
              <th>Hạng mục & Nội dung Tiêu chí</th>
              <th>Điều kiện Ghi nhận (Trạng thái cuối cùng)</th>
              <th style="width: 90px; text-align: center;">Điểm</th>
            </tr>
          </thead>
          <tbody>
            ${RG_CRITERIA.map(grp => `
              <tr>
                <td colspan="4" class="rg-mission-group">${grp.group}</td>
              </tr>
              ${grp.items.map(it => `
                <tr>
                  <td><span class="badge-code">${it.label}</span></td>
                  <td><strong>${it.title}</strong></td>
                  <td style="color: var(--text-muted); font-size: 12.5px;">${it.cond}</td>
                  <td class="mono-num" style="text-align: center; font-weight: 800; color: var(--navy-800);">${it.pts} đ</td>
                </tr>
              `).join("")}
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  if (activeRuleTab === "RD") {
    return `
      <div>
        <div style="background: var(--rd-light); border: 1px solid #BFDBFE; border-left: 4px solid var(--rd-primary); border-radius: 8px; padding: 12px 16px; margin-bottom: 14px;">
          <div style="font-weight: 800; color: var(--rd-primary); font-size: 14px; margin-bottom: 6px;">
            📌 Hướng dẫn Phiếu đánh giá Thiết Kế Robot [BM04-RD] (Tối đa 40 điểm):
          </div>
          <ul style="font-size: 13px; color: var(--text-secondary); margin-left: 18px; line-height: 1.7;">
            <li><strong>Cấu trúc phiếu chấm:</strong> Đánh giá qua <strong>05 nhóm tiêu chí</strong> (gồm 10 dòng tiêu chí từ <code>1.1</code> đến <code>5.2</code>).</li>
            <li><strong>Thang điểm đánh giá (4 mức độ):</strong>
              <span class="badge-code" style="margin-left: 4px;">Mức 1: Bắt đầu (1 điểm)</span>
              <span class="badge-code" style="margin-left: 4px;">Mức 2: Phát triển (2 điểm)</span>
              <span class="badge-code" style="margin-left: 4px;">Mức 3: Hoàn thành (3 điểm)</span>
              <span class="badge-code" style="margin-left: 4px;">Mức 4: Vượt trội (4 điểm)</span>
            </li>
            <li><strong>Tích hợp Giá Trị Cốt Lõi:</strong> 05 tiêu chí gắn nhãn <span class="badge-cv">⚙♥ CV</span> (<code>1.2</code>, <code>2.1</code>, <code>4.2</code>, <code>5.1</code>, <code>5.2</code>) đồng thời được cộng tự động vào điểm <strong>Giá Trị Cốt Lõi (Tối đa 20 điểm)</strong>.</li>
          </ul>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 85px;">Tiêu chí</th>
              <th>Bắt đầu (1 điểm)</th>
              <th>Phát triển (2 điểm)</th>
              <th>Hoàn thành (3 điểm)</th>
            </tr>
          </thead>
          <tbody>
            ${RD_SECTIONS.map(sec => `
              <tr>
                <td colspan="4" class="rg-mission-group">${sec.section} – ${sec.desc}</td>
              </tr>
              ${sec.rows.map(r => `
                <tr>
                  <td>
                    <span class="badge-code">${r.code}</span>
                    ${r.isCV ? `<div style="margin-top:4px;"><span class="badge-cv">⚙♥ CV</span></div>` : ""}
                  </td>
                  <td style="font-size: 12.5px;">${r.l1}</td>
                  <td style="font-size: 12.5px;">${r.l2}</td>
                  <td style="font-size: 12.5px;">${r.l3}</td>
                </tr>
              `).join("")}
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  if (activeRuleTab === "IP") {
    return `
      <div>
        <div style="background: var(--ip-light); border: 1px solid #99F6E4; border-left: 4px solid var(--ip-primary); border-radius: 8px; padding: 12px 16px; margin-bottom: 14px;">
          <div style="font-weight: 800; color: var(--ip-primary); font-size: 14px; margin-bottom: 6px;">
            📌 Hướng dẫn Phiếu đánh giá Dự Án Đổi Mới [BM05-IP] (Tối đa 40 điểm):
          </div>
          <ul style="font-size: 13px; color: var(--text-secondary); margin-left: 18px; line-height: 1.7;">
            <li><strong>Cấu trúc phiếu chấm:</strong> Đánh giá giải pháp sáng tạo của nhóm qua <strong>05 nhóm tiêu chí</strong> (gồm 10 dòng tiêu chí từ <code>1.1</code> đến <code>5.2</code>).</li>
            <li><strong>Thang điểm đánh giá (4 mức độ):</strong>
              <span class="badge-code" style="margin-left: 4px; color: var(--ip-primary);">Mức 1: Bắt đầu (1 điểm)</span>
              <span class="badge-code" style="margin-left: 4px; color: var(--ip-primary);">Mức 2: Phát triển (2 điểm)</span>
              <span class="badge-code" style="margin-left: 4px; color: var(--ip-primary);">Mức 3: Hoàn thành (3 điểm)</span>
              <span class="badge-code" style="margin-left: 4px; color: var(--ip-primary);">Mức 4: Vượt trội (4 điểm)</span>
            </li>
            <li><strong>Tích hợp Giá Trị Cốt Lõi:</strong> 05 tiêu chí gắn nhãn <span class="badge-cv">⚙♥ CV</span> (<code>1.2</code>, <code>2.2</code>, <code>3.1</code>, <code>5.1</code>, <code>5.2</code>) đồng thời được cộng tự động vào điểm <strong>Giá Trị Cốt Lõi (Tối đa 20 điểm)</strong>.</li>
          </ul>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 85px;">Tiêu chí</th>
              <th>Bắt đầu (1 điểm)</th>
              <th>Phát triển (2 điểm)</th>
              <th>Hoàn thành (3 điểm)</th>
            </tr>
          </thead>
          <tbody>
            ${IP_SECTIONS.map(sec => `
              <tr>
                <td colspan="4" class="rg-mission-group">${sec.section} – ${sec.desc}</td>
              </tr>
              ${sec.rows.map(r => `
                <tr>
                  <td>
                    <span class="badge-code">${r.code}</span>
                    ${r.isCV ? `<div style="margin-top:4px;"><span class="badge-cv">⚙♥ CV</span></div>` : ""}
                  </td>
                  <td style="font-size: 12.5px;">${r.l1}</td>
                  <td style="font-size: 12.5px;">${r.l2}</td>
                  <td style="font-size: 12.5px;">${r.l3}</td>
                </tr>
              `).join("")}
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  return `
    <div>
      <h4 style="font-size: 15px; font-weight: 800; color: var(--navy-800); margin-bottom: 8px;">
        1. Cách tính điểm Giá Trị Cốt Lõi (Core Values – Tối đa 40 điểm)
      </h4>
      <p style="font-size: 13.5px; color: var(--text-secondary); margin-bottom: 12px;">
        Theo quy chuẩn chấm thi FLL Challenge tích hợp, điểm <strong>Giá Trị Cốt Lõi (40 điểm)</strong> được tổng hợp tự động từ 10 tiêu chí có biểu tượng <span class="badge-cv">⚙♥ CV</span> trên 2 phiếu thuyết trình:
      </p>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
        <div style="background: var(--rd-light); border: 1px solid #BFDBFE; border-radius: 8px; padding: 12px 14px;">
          <div style="font-weight: 800; color: var(--rd-primary); font-size: 13.5px; margin-bottom: 6px;">
            ⚙️ Từ phiếu Thiết Kế Robot (Tối đa 20 điểm):
          </div>
          <ul style="font-size: 13px; color: var(--text-primary); margin-left: 18px; line-height: 1.7;">
            <li>Tiêu chí <code>1.2</code>: Khám phá & sử dụng nguồn lực (1–4 điểm)</li>
            <li>Tiêu chí <code>2.1</code>: Hợp tác đóng góp ý tưởng (1–4 điểm)</li>
            <li>Tiêu chí <code>4.2</code>: Cải thiện dựa trên thử nghiệm (1–4 điểm)</li>
            <li>Tiêu chí <code>5.1</code>: Chia sẻ quy trình & bài học (1–4 điểm)</li>
            <li>Tiêu chí <code>5.2</code>: Niềm tự hào & sự nhiệt tình (1–4 điểm)</li>
          </ul>
        </div>
        <div style="background: var(--ip-light); border: 1px solid #99F6E4; border-radius: 8px; padding: 12px 14px;">
          <div style="font-weight: 800; color: var(--ip-primary); font-size: 13.5px; margin-bottom: 6px;">
            💡 Từ phiếu Dự Án Đổi Mới (Tối đa 20 điểm):
          </div>
          <ul style="font-size: 13px; color: var(--text-primary); margin-left: 18px; line-height: 1.7;">
            <li>Tiêu chí <code>1.2</code>: Khám phá từ nhiều nguồn nghiên cứu (1–4 điểm)</li>
            <li>Tiêu chí <code>2.2</code>: Hợp tác tham gia của toàn đội (1–4 điểm)</li>
            <li>Tiêu chí <code>3.1</code>: Đổi mới sáng tạo trong giải pháp (1–4 điểm)</li>
            <li>Tiêu chí <code>5.1</code>: Tác động của giải pháp tới cộng đồng (1–4 điểm)</li>
            <li>Tiêu chí <code>5.2</code>: Niềm tự hào & sự nhiệt tình (1–4 điểm)</li>
          </ul>
        </div>
      </div>

      <div class="tiebreaker-box">
        <h4>⚖️ QUY TẮC XỬ LÝ ĐỒNG ĐIỂM (TIE-BREAKER RULES) KHI XÉT CHỌN TOP 4 ĐỘI TUYỂN</h4>
        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
          Các nhóm được xếp hạng từ 1 đến 8 theo <strong>Tổng điểm toàn diện (Tối đa 230đ)</strong> từ cao xuống thấp để lấy <strong>04 nhóm cao nhất</strong>.
          Trong trường hợp có từ 02 nhóm trở lên bằng tổng điểm nhau, hệ thống tự động phân định thứ hạng lần lượt theo 04 tiêu chí ưu tiên sau:
        </p>
        <div class="tiebreaker-steps">
          <div class="tb-step">
            <span class="tb-num">1</span>
            <span><strong>Điểm Robot Game cao hơn</strong> (Tối đa 110đ)</span>
          </div>
          <div class="tb-step">
            <span class="tb-num">2</span>
            <span><strong>Điểm Thiết Kế Robot (Robot Design) cao hơn</strong> (Tối đa 40đ)</span>
          </div>
          <div class="tb-step">
            <span class="tb-num">3</span>
            <span><strong>Điểm Giá Trị Cốt Lõi (Core Values) cao hơn</strong> (Tối đa 40đ)</span>
          </div>
          <div class="tb-step">
            <span class="tb-num">4</span>
            <span><strong>Thời gian hoàn thành Robot Game nhanh hơn</strong> (Số giây nhỏ hơn)</span>
          </div>
        </div>
      </div>
    </div>
  `;
}

// ============================================================================
// MÀN HÌNH GIÁM KHẢO HẠNG MỤC ROBOT GAME [BM01-RG]
// ============================================================================

function selectTeamForJudge(teamId) {
  selectedTeamId = teamId;
  saveSessionState();
  renderApp();
}

function toggleRgCriterion(runKey, code) {
  if (!currentUser || (currentUser.role !== "RG" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.robotGame.completed && team.robotGame.updatedBy && team.robotGame.updatedBy !== currentUser.id) {
    showToast(`⚠️ Nhóm ${team.id} đang do ${team.robotGame.updatedBy} phụ trách chấm! Bạn chỉ có thể sửa/xóa nhóm do mình phụ trách.`);
    return;
  }
  if (!team.robotGame[runKey]) team.robotGame[runKey] = {};
  team.robotGame[runKey][code] = !team.robotGame[runKey][code];
  if (!team.robotGame.updatedBy) team.robotGame.updatedBy = currentUser.id;
  saveData(false);
  renderApp();
}

function updateRgTime(runTimeKey, val) {
  if (!currentUser || (currentUser.role !== "RG" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.robotGame.completed && team.robotGame.updatedBy && team.robotGame.updatedBy !== currentUser.id) {
    showToast(`⚠️ Nhóm ${team.id} đang do ${team.robotGame.updatedBy} phụ trách chấm!`);
    renderApp();
    return;
  }
  const sec = Math.max(0, Math.min(240, parseInt(val, 10) || 0));
  team.robotGame[runTimeKey] = sec;
  if (!team.robotGame.updatedBy) team.robotGame.updatedBy = currentUser.id;
  saveData(false);
  renderApp();
}

function updateTeamNameInput(val) {
  if (!currentUser) return;
  const team = appData.teams[selectedTeamId];
  team.teamName = val;
  saveData(false);
}

function saveRobotGameTeam() {
  if (!currentUser || (currentUser.role !== "RG" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.robotGame.completed && team.robotGame.updatedBy && team.robotGame.updatedBy !== currentUser.id && team.robotGame.updatedBy !== "Quản trị viên") {
    showToast(`⚠️ Nhóm ${team.id} đã được ${team.robotGame.updatedBy} phụ trách chấm!`);
    return;
  }
  const r1 = calcRunScore(team.robotGame.run1);
  const r2 = calcRunScore(team.robotGame.run2);
  if (r1 === 0 && r2 === 0) {
    showToast(`⚠️ Vui lòng tích chọn ít nhất 1 tiêu chí điểm trước khi bấm Lưu điểm (Nếu muốn xóa điểm, hãy bấm nút 'Xóa điểm')!`);
    return;
  }
  team.robotGame.completed = true;
  team.robotGame.updatedBy = currentUser.id;
  team.robotGame.updatedAt = new Date().toLocaleTimeString("vi-VN");
  saveData(true);
  showToast(`✅ Đã lưu và đồng bộ điểm Robot Game cho ${team.code}!`);
  renderApp();
}

function resetTeamRobotGame() {
  if (!currentUser || (currentUser.role !== "RG" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.robotGame.updatedBy && team.robotGame.updatedBy !== currentUser.id) {
    showToast(`⚠️ Bạn không thể xóa dữ liệu của Nhóm ${team.id} vì nhóm này do ${team.robotGame.updatedBy} phụ trách chấm!`);
    return;
  }
  if (!confirm(`Bạn có chắc chắn muốn xóa dữ liệu chấm Robot Game của riêng ${team.code} (${team.teamName})? Các nhóm khác sẽ KHÔNG bị ảnh hưởng.`)) return;

  team.robotGame = {
    completed: false,
    updatedBy: "",
    updatedAt: "",
    run1: {},
    run1TimeSec: 180,
    run2: {},
    run2TimeSec: 180
  };
  saveData(true);
  showToast(`🗑️ Đã xóa dữ liệu Robot Game của ${team.code}. Các nhóm khác được giữ nguyên.`);
  renderApp();
}

function renderJudgeToolbar() {
  const isAdmin = currentUser && currentUser.role === "ADMIN";
  const st = getAllTeamsStatus();
  const isPublished = isResultPublishedByAdmin();
  const cloudCfg = getCloudCfg();

  return `
    ${isAdmin ? `
      <div class="admin-publish-banner no-print">
        <div>
          <div style="font-size: 13.5px; font-weight: 800; color: #FDE047;">
            🛡️ QUẢN LÝ CÔNG BỐ KẾT QUẢ
          </div>
          <div style="font-size: 12.5px; color: #E2E8F0; margin-top: 3px;">
            Trạng thái:
            <strong style="color: ${isPublished ? "#34D399" : "#FBBF24"};">
              ${isPublished ? "🔓 Đã công bố" : "🔒 Đang ẩn điểm (Chỉ hiện 'Đã cập nhật điểm')"}
            </strong>
            • Tiến độ: <strong>${st.fullDoneCount}/8 nhóm</strong>
          </div>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button
            class="btn ${isPublished ? "btn-danger" : "btn-gold"}"
            style="font-size: 13px; padding: 8px 14px;"
            onclick="toggleAdminPublishResults()"
          >
            ${isPublished ? "🔒 Khóa công bố" : "🔓 Công bố kết quả"}
          </button>
          <button
            class="btn btn-outline-light"
            style="font-size: 12.5px; padding: 8px 14px;"
            onclick="openPrintCategoryModal('SUMMARY', 'ALL')"
          >
            🖨️ In tổng hợp
          </button>
        </div>
      </div>
    ` : ""}

    <div class="sync-bar no-print">
      <div>
        <strong>${isAdmin ? "🛡️ Công cụ quản lý:" : `👤 Giám khảo (${currentUser?.id}):`}</strong>
        <span style="color: var(--text-muted); margin-left: 6px;">
          In phiếu điểm và đồng bộ dữ liệu trực tuyến.
        </span>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        <button class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;" onclick="exportExcelWorkbook('ALL')">
          📊 Xuất Excel
        </button>
        <button class="btn btn-navy" style="padding: 6px 12px; font-size: 12px;" onclick="toggleCloudModal()">
          ☁️ Đồng bộ Online ${cloudCfg.url ? "✓" : ""}
        </button>
        <button class="btn btn-outline" style="padding: 6px 12px; font-size: 12px;" onclick="exportJsonData()">
          ⬇️ Sao lưu
        </button>
        ${isAdmin ? `
          <label class="btn btn-outline" style="padding: 6px 12px; font-size: 12px; margin: 0;">
            ⬆️ Nhập file
            <input type="file" accept=".json" style="display: none;" onchange="importJsonData(event)" />
          </label>
          <button class="btn btn-outline" style="padding: 6px 12px; font-size: 12px;" onclick="loadDemoScenario()">
            ⚡ Dữ liệu mẫu
          </button>
          <button class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;" onclick="resetAllScores()">
            🗑️ Xóa tất cả
          </button>
        ` : ""}
      </div>
    </div>

    <div id="cloudConfigPanel" style="display: none;" class="card no-print">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 10px;">
        <div>
          <h4 style="color: var(--navy-800); font-size: 15px;">
            ☁️ Kết nối Google Sheets trực tuyến
          </h4>
          <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 3px;">
            Dán liên kết Web App từ Google Sheets để tự động lưu và đồng bộ điểm giữa các máy chấm thi.
          </p>
        </div>
        ${isAdmin ? `
          <button class="btn btn-primary" style="font-size: 12px; padding: 8px 14px;" onclick="copyAppsScriptTemplate()">
            📋 Sao chép mã Apps Script
          </button>
        ` : ""}
      </div>
      <div style="display: grid; grid-template-columns: 1fr auto auto; gap: 10px; align-items: end;">
        <div>
          <label style="font-size: 12px; font-weight: 700;">Liên kết Web App Google Apps Script</label>
          <input id="cloudUrlInput" type="password" class="form-control mono-num" placeholder="https://script.google.com/macros/s/.../exec" value="${cloudCfg.url || ""}" />
        </div>
        <button class="btn btn-primary" onclick="saveCloudCfg()">💾 Lưu kết nối</button>
        <button class="btn btn-navy" onclick="pullFromCloud()">🔄 Tải dữ liệu</button>
      </div>
      ${isAdmin ? `
        <div style="margin-top: 14px; padding-top: 12px; border-top: 1px dashed var(--border-strong);">
          <div style="font-size: 12.5px; font-weight: 800; color: var(--navy-800); margin-bottom: 6px;">
            🔐 Tạo mã tài khoản mới:
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 8px; align-items: end;">
            <div>
              <label style="font-size: 11.5px; font-weight: 700;">Tài khoản</label>
              <input id="genAccUser" class="form-control mono-num" style="font-size: 12px; padding: 6px 10px;" placeholder="Nhập tài khoản..." />
            </div>
            <div>
              <label style="font-size: 11.5px; font-weight: 700;">Mật khẩu</label>
              <input id="genAccPass" type="text" class="form-control mono-num" style="font-size: 12px; padding: 6px 10px;" placeholder="Nhập mật khẩu..." />
            </div>
            <div>
              <label style="font-size: 11.5px; font-weight: 700;">Phân quyền</label>
              <select id="genAccRole" class="form-control" style="font-size: 12px; padding: 6px 10px;">
                <option value="RG">Robot Game</option>
                <option value="RUBRIC">TK Robot & Dự án</option>
                <option value="ADMIN">Quản trị viên</option>
              </select>
            </div>
            <button class="btn btn-outline" style="font-size: 12px; padding: 7px 12px;" onclick="generateStretchedRecordSnippet()">
              ⚙️ Tạo mã
            </button>
          </div>
          <div id="genAccResult" class="mono-num" style="margin-top: 6px; font-size: 11px; color: var(--teal-700); word-break: break-all;"></div>
        </div>
      ` : ""}
    </div>
  `;
}

function renderJudgeRgView() {
  if (!currentUser || (currentUser.role !== "RG" && currentUser.role !== "ADMIN")) {
    return `<div class="card">🔒 Vui lòng đăng nhập bằng tài khoản Giám khảo được phân công để truy cập phần nhập liệu Robot Game.</div>`;
  }

  const st = getAllTeamsStatus();
  const team = appData.teams[selectedTeamId];
  const sum = computeTeamSummary(team);
  const isAdmin = currentUser.role === "ADMIN";
  const showAllScores = canShowScoreDetails();
  const canModifyThisTeam = isAdmin || !team.robotGame.updatedBy || team.robotGame.updatedBy === currentUser.id || team.robotGame.updatedBy === "Quản trị viên";
  const isLockedByOtherJudge = !canModifyThisTeam && team.robotGame.completed && !showAllScores;

  return `
    <div class="judge-header-bar">
      <div>
        <div style="font-size: 12px; color: #99F6E4; font-weight: 700;">TRƯỜNG THCS & THPT ĐINH THIỆN LÝ • BIỂU MẪU [BM01-RG] • 📍 PHÒNG A211 (11h45 – 13h15, 30/10)</div>
        <h2 style="font-size: 20px; font-weight: 800;">🤖 MÀN HÌNH CHẤM ĐIỂM ROBOT GAME (${currentUser.id})</h2>
      </div>
      <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
        <button class="btn btn-outline-light" style="font-size: 12.5px; padding: 7px 12px;" onclick="openPrintCategoryModal('RG', 'SINGLE')">
          🖨️ In phiếu
        </button>
        ${(isAdmin || showAllScores) ? `
          <button class="btn btn-gold" style="font-size: 12.5px; padding: 7px 12px;" onclick="openPrintCategoryModal('RG', 'ALL')">
            🖨️ In cả 8 nhóm
          </button>
        ` : ""}
        <span class="status-badge ${st.rgDoneCount === 8 ? "status-ready" : "status-locked"}">
          Đã cập nhật: ${st.rgDoneCount}/8 nhóm
        </span>
      </div>
    </div>

    ${renderJudgeToolbar()}

    <!-- CHỌN NHÓM TỪ 1 ĐẾN 8 (CHỈ HIỂN THỊ 'ĐÃ CẬP NHẬT ĐIỂM' KHI ADMIN CHƯA CHO PHÉP CÔNG BỐ) -->
    <div class="team-selector-grid">
      ${st.summaries.map(s => `
        <div class="team-select-btn ${s.id === selectedTeamId ? "active" : ""} ${s.isRgDone ? "done" : ""}" onclick="selectTeamForJudge(${s.id})">
          <span class="t-num">NHÓM ${s.id}</span>
          <span class="t-status mono-num">
            ${s.isRgDone
              ? (showAllScores ? `✓ ${s.robotGameScore}đ (${s.robotGameTimeSec}s)` : "✓ Đã cập nhật điểm")
              : "⏳ Chưa cập nhật"}
          </span>
        </div>
      `).join("")}
    </div>

    ${isLockedByOtherJudge ? `
      <div class="card" style="text-align: center; padding: 36px 24px;">
        <h3 style="color: var(--navy-800); margin-bottom: 8px;">✅ ${team.code} (${team.teamName}) – Đã Cập Nhật Điểm Robot Game</h3>
        <p style="font-size: 13.5px; color: var(--text-muted); max-width: 640px; margin: 0 auto;">
          Nhóm này đã được cập nhật điểm bởi <strong>${team.robotGame.updatedBy}</strong> lúc ${team.robotGame.updatedAt}.<br/>
          Theo quy định bảo mật của Ban Tổ Chức, <strong>thông tin điểm số và kết quả chỉ được hiển thị khi Quản trị viên (Admin) cho phép in & công bố kết quả</strong>.
        </p>
      </div>
    ` : `
      <!-- PHIẾU CHẤM ROBOT GAME CỦA NHÓM ĐANG CHỌN -->
      <div class="card">
        <div class="card-header" style="flex-wrap: wrap; gap: 10px;">
          <div>
            <h3>📋 Phiếu Chấm Điểm Robot Game [BM01-RG] – ${team.code} (📍 Phòng A211)</h3>
            <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">
              Ghi nhận theo trạng thái cuối cùng của vật thể và robot. Điểm chính thức = Điểm cao nhất trong 2 lượt chạy.
            </p>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 12px; color: var(--text-muted);">
              ${showAllScores ? "ĐIỂM CHÍNH THỨC HIỆN TẠI" : "ĐIỂM TẠM TÍNH (BẢO MẬT ĐẾN KHI ADMIN DUYỆT IN)"}
            </div>
            <div class="mono-num" style="font-size: 24px; font-weight: 900; color: var(--teal-700);">
              ${sum.robotGameScore} / 110 đ
            </div>
            <div class="mono-num" style="font-size: 12px; font-weight: 700; color: var(--navy-800);">
              (${sum.bestRunLabel} • Thời gian: ${formatSeconds(sum.robotGameTimeSec)})
            </div>
          </div>
        </div>

        <!-- THÔNG TIN ĐỘI & THỜI GIAN 2 LƯỢT -->
        <div style="display: grid; grid-template-columns: 1.4fr 1fr 1fr; gap: 16px; margin-bottom: 18px; background: var(--bg-elevated); padding: 14px; border-radius: 8px;">
          <div>
            <label style="font-size: 12px; font-weight: 700; color: var(--text-secondary);">Tên Đội / Nhóm ${team.id}:</label>
            <input type="text" class="form-control" value="${team.teamName}" onchange="updateTeamNameInput(this.value)" />
          </div>
          <div>
            <label style="font-size: 12px; font-weight: 700; color: var(--navy-800);">⏱️ Thời gian hoàn thành LƯỢT 1 (Giây, tối đa 240s):</label>
            <input type="number" min="1" max="240" class="form-control mono-num" value="${team.robotGame.run1TimeSec}" onchange="updateRgTime('run1TimeSec', this.value)" />
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 3px;">Quy đổi: ${formatSeconds(team.robotGame.run1TimeSec)}</div>
          </div>
          <div>
            <label style="font-size: 12px; font-weight: 700; color: var(--navy-800);">⏱️ Thời gian hoàn thành LƯỢT 2 (Giây, tối đa 240s):</label>
            <input type="number" min="1" max="240" class="form-control mono-num" value="${team.robotGame.run2TimeSec}" onchange="updateRgTime('run2TimeSec', this.value)" />
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 3px;">Quy đổi: ${formatSeconds(team.robotGame.run2TimeSec)}</div>
          </div>
        </div>

        <!-- BẢNG CHẤM CHI TIẾT LƯỢT 1 & LƯỢT 2 -->
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 70px; text-align: center;">Mã</th>
              <th>Nội dung Tiêu chí Chấm điểm</th>
              <th>Điều kiện Ghi nhận (Theo Rulebook)</th>
              <th style="width: 85px; text-align: center;">Điểm Chuẩn</th>
              <th style="width: 150px; text-align: center;">LƯỢT 1 (${sum.r1Score}đ)</th>
              <th style="width: 150px; text-align: center;">LƯỢT 2 (${sum.r2Score}đ)</th>
            </tr>
          </thead>
          <tbody>
            ${RG_CRITERIA.map(grp => `
              <tr>
                <td colspan="6" class="rg-mission-group">${grp.group}</td>
              </tr>
              ${grp.items.map(it => {
                const c1 = Boolean(team.robotGame.run1 && team.robotGame.run1[it.code]);
                const c2 = Boolean(team.robotGame.run2 && team.robotGame.run2[it.code]);
                return `
                  <tr>
                    <td style="text-align: center;"><span class="badge-code">${it.label}</span></td>
                    <td><strong>${it.title}</strong></td>
                    <td style="font-size: 12.5px; color: var(--text-muted);">${it.cond}</td>
                    <td class="mono-num" style="text-align: center; font-weight: 800;">${it.pts} đ</td>
                    <td style="text-align: center;">
                      <label class="check-label ${c1 ? "checked" : ""}">
                        <input type="checkbox" ${c1 ? "checked" : ""} onchange="toggleRgCriterion('run1', '${it.code}')" />
                        <span class="mono-num">${c1 ? `+${it.pts} đ` : "0 đ"}</span>
                      </label>
                    </td>
                    <td style="text-align: center;">
                      <label class="check-label ${c2 ? "checked" : ""}">
                        <input type="checkbox" ${c2 ? "checked" : ""} onchange="toggleRgCriterion('run2', '${it.code}')" />
                        <span class="mono-num">${c2 ? `+${it.pts} đ` : "0 đ"}</span>
                      </label>
                    </td>
                  </tr>
                `;
              }).join("")}
            `).join("")}
            <tr style="background: #FEF3C7; font-weight: 800;">
              <td colspan="3" style="text-align: right; color: var(--navy-800);">TỔNG ĐIỂM TỪNG LƯỢT CHẠY (TỐI ĐA 110 ĐIỂM):</td>
              <td class="mono-num" style="text-align: center;">110 đ</td>
              <td class="mono-num" style="text-align: center; font-size: 16px; color: var(--navy-800);">${sum.r1Score} / 110 đ</td>
              <td class="mono-num" style="text-align: center; font-size: 16px; color: var(--navy-800);">${sum.r2Score} / 110 đ</td>
            </tr>
          </tbody>
        </table>

        <!-- NÚT LƯU, IN PHIẾU HẠNG MỤC & XÓA RIÊNG NHÓM ĐANG PHỤ TRÁCH -->
        <div style="margin-top: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; padding-top: 16px; border-top: 2px solid var(--bg-elevated);">
          <div style="font-size: 13px; color: var(--text-secondary);">
            ${team.robotGame.completed
              ? `✅ <strong>Đã cập nhật điểm:</strong> Phụ trách chấm bởi <strong>${team.robotGame.updatedBy}</strong> lúc ${team.robotGame.updatedAt}`
              : `⚠️ Nhóm ${team.id} chưa được bấm nút Lưu & Cập nhật điểm Robot Game.`}
          </div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <button class="btn btn-outline" style="padding: 10px 14px; font-size: 13px;" onclick="openPrintCategoryModal('RG', 'SINGLE')">
              🖨️ In phiếu
            </button>
            <button class="btn btn-outline" style="padding: 10px 14px; font-size: 13px;" onclick="exportExcelWorkbook('RG')">
              📊 Xuất Excel
            </button>
            ${canModifyThisTeam ? `
              <button class="btn btn-danger" style="padding: 10px 14px; font-size: 13px;" onclick="resetTeamRobotGame()">
                🗑️ Xóa điểm
              </button>
              <button class="btn btn-primary" style="padding: 10px 20px; font-size: 14px;" onclick="saveRobotGameTeam()">
                💾 Lưu điểm
              </button>
            ` : `
              <span class="status-badge status-locked" style="padding: 10px 14px; font-size: 13px;">
                🔒 Do ${team.robotGame.updatedBy} phụ trách
              </span>
            `}
          </div>
        </div>
      </div>
    `}
  `;
}

// ============================================================================
// MÀN HÌNH GIÁM KHẢO HẠNG MỤC THIẾT KẾ ROBOT [BM04-RD] & DỰ ÁN ĐỔI MỚI [BM05-IP]
// ============================================================================

function switchJudgeRubricTab(tab) {
  activeRubricTab = tab;
  saveSessionState();
  renderApp();
}

function selectRubricLevel(type, code, level) {
  if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.rubric.completed && team.rubric.updatedBy && team.rubric.updatedBy !== currentUser.id) {
    showToast(`⚠️ Nhóm ${team.id} đang do ${team.rubric.updatedBy} phụ trách chấm! Bạn chỉ có thể sửa/xóa nhóm do mình phụ trách.`);
    return;
  }
  if (type === "RD") {
    team.rubric.rdScores[code] = level;
  } else {
    team.rubric.ipScores[code] = level;
  }
  if (!team.rubric.updatedBy) team.rubric.updatedBy = currentUser.id;
  saveData(false);
  renderApp();
}

function updateRubricNote(type, code, noteVal) {
  if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.rubric.completed && team.rubric.updatedBy && team.rubric.updatedBy !== currentUser.id) {
    showToast(`⚠️ Nhóm ${team.id} đang do ${team.rubric.updatedBy} phụ trách chấm!`);
    renderApp();
    return;
  }
  if (type === "RD") {
    team.rubric.rdNotes[code] = noteVal;
  } else {
    team.rubric.ipNotes[code] = noteVal;
  }
  if (!team.rubric.updatedBy) team.rubric.updatedBy = currentUser.id;
  saveData(false);
}

function fillDefaultRubric3ForCurrentTeam() {
  if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.rubric.completed && team.rubric.updatedBy && team.rubric.updatedBy !== currentUser.id) {
    showToast(`⚠️ Nhóm ${team.id} đang do ${team.rubric.updatedBy} phụ trách chấm!`);
    return;
  }
  RD_SECTIONS.forEach(s => s.rows.forEach(r => {
    if (!team.rubric.rdScores[r.code]) team.rubric.rdScores[r.code] = 3;
  }));
  IP_SECTIONS.forEach(s => s.rows.forEach(r => {
    if (!team.rubric.ipScores[r.code]) team.rubric.ipScores[r.code] = 3;
  }));
  if (!team.rubric.updatedBy) team.rubric.updatedBy = currentUser.id;
  saveData(false);
  renderApp();
}

function saveRubricTeam() {
  if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.rubric.completed && team.rubric.updatedBy && team.rubric.updatedBy !== currentUser.id) {
    showToast(`⚠️ Nhóm ${team.id} đã được ${team.rubric.updatedBy} phụ trách chấm!`);
    return;
  }

  let rdCount = 0;
  let ipCount = 0;
  RD_SECTIONS.forEach(s => s.rows.forEach(r => { if (team.rubric.rdScores[r.code]) rdCount++; }));
  IP_SECTIONS.forEach(s => s.rows.forEach(r => { if (team.rubric.ipScores[r.code]) ipCount++; }));

  if (rdCount < 10 || ipCount < 10) {
    showToast(`⚠️ Vui lòng đánh dấu đủ 10/10 tiêu chí Thiết Kế Robot (hiện ${rdCount}/10) và 10/10 tiêu chí Dự Án Đổi Mới (hiện ${ipCount}/10)!`);
    return;
  }

  team.rubric.completed = true;
  team.rubric.updatedBy = currentUser.id;
  team.rubric.updatedAt = new Date().toLocaleTimeString("vi-VN");
  saveData(true);
  showToast(`✅ Đã lưu điểm Thiết Kế Robot, Dự Án Đổi Mới & Giá Trị Cốt Lõi cho ${team.code}!`);
  renderApp();
}

function resetTeamRubric() {
  if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) return;
  const team = appData.teams[selectedTeamId];
  if (currentUser.role !== "ADMIN" && team.rubric.updatedBy && team.rubric.updatedBy !== currentUser.id) {
    showToast(`⚠️ Bạn không thể xóa dữ liệu của Nhóm ${team.id} vì nhóm này do ${team.rubric.updatedBy} phụ trách chấm!`);
    return;
  }
  if (!confirm(`Bạn có chắc chắn muốn xóa dữ liệu chấm Thiết Kế Robot & Dự Án Đổi Mới của riêng ${team.code} (${team.teamName})? Các nhóm khác sẽ KHÔNG bị ảnh hưởng.`)) return;

  team.rubric = {
    completed: false,
    updatedBy: "",
    updatedAt: "",
    rdScores: {},
    rdNotes: {},
    ipScores: {},
    ipNotes: {}
  };
  saveData(true);
  showToast(`🗑️ Đã xóa dữ liệu Thiết Kế Robot & Dự Án Đổi Mới của ${team.code}. Các nhóm khác được giữ nguyên.`);
  renderApp();
}

function renderJudgeRubricView() {
  if (!currentUser || (currentUser.role !== "RUBRIC" && currentUser.role !== "ADMIN")) {
    return `<div class="card">🔒 Vui lòng đăng nhập bằng tài khoản Giám khảo được phân công để truy cập phần chấm Thiết Kế Robot & Dự Án Đổi Mới.</div>`;
  }

  const st = getAllTeamsStatus();
  const team = appData.teams[selectedTeamId];
  const sum = computeTeamSummary(team);
  const isAdmin = currentUser.role === "ADMIN";
  const showAllScores = canShowScoreDetails();
  const canModifyThisTeam = isAdmin || !team.rubric.updatedBy || team.rubric.updatedBy === currentUser.id || team.rubric.updatedBy === "Quản trị viên";
  const isLockedByOtherJudge = !canModifyThisTeam && team.rubric.completed && !showAllScores;

  let rdCount = 0;
  let ipCount = 0;
  RD_SECTIONS.forEach(s => s.rows.forEach(r => { if (team.rubric.rdScores[r.code]) rdCount++; }));
  IP_SECTIONS.forEach(s => s.rows.forEach(r => { if (team.rubric.ipScores[r.code]) ipCount++; }));

  const isRD = activeRubricTab === "RD";
  const sections = isRD ? RD_SECTIONS : IP_SECTIONS;
  const scoresMap = isRD ? team.rubric.rdScores : team.rubric.ipScores;
  const notesMap = isRD ? team.rubric.rdNotes : team.rubric.ipNotes;

  return `
    <div class="judge-header-bar">
      <div>
        <div style="font-size: 12px; color: #99F6E4; font-weight: 700;">TRƯỜNG THCS & THPT ĐINH THIỆN LÝ • BIỂU MẪU [BM04-RD] & [BM05-IP] • 📍 PHÒNG B217 (11h45 – 13h15, 30/10)</div>
        <h2 style="font-size: 20px; font-weight: 800;">⚙️💡 MÀN HÌNH CHẤM THIẾT KẾ ROBOT & DỰ ÁN ĐỔI MỚI (${currentUser.id})</h2>
      </div>
      <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
        <button class="btn btn-outline-light" style="font-size: 12px; padding: 7px 11px;" onclick="openPrintCategoryModal('RD', 'SINGLE')">
          🖨️ In TK Robot
        </button>
        <button class="btn btn-outline-light" style="font-size: 12px; padding: 7px 11px;" onclick="openPrintCategoryModal('IP', 'SINGLE')">
          🖨️ In Dự án
        </button>
        ${(isAdmin || showAllScores) ? `
          <button class="btn btn-gold" style="font-size: 12px; padding: 7px 11px;" onclick="openPrintCategoryModal('${isRD ? "RD" : "IP"}', 'ALL')">
            🖨️ In cả 8 nhóm
          </button>
        ` : ""}
        <span class="status-badge ${st.rubricDoneCount === 8 ? "status-ready" : "status-locked"}">
          Đã cập nhật: ${st.rubricDoneCount}/8 nhóm
        </span>
      </div>
    </div>

    ${renderJudgeToolbar()}

    <!-- CHỌN NHÓM TỪ 1 ĐẾN 8 (CHỈ HIỂN THỊ 'ĐÃ CẬP NHẬT ĐIỂM' KHI ADMIN CHƯA CHO PHÉP CÔNG BỐ) -->
    <div class="team-selector-grid">
      ${st.summaries.map(s => `
        <div class="team-select-btn ${s.id === selectedTeamId ? "active" : ""} ${s.isRubricDone ? "done" : ""}" onclick="selectTeamForJudge(${s.id})">
          <span class="t-num">NHÓM ${s.id}</span>
          <span class="t-status mono-num">
            ${s.isRubricDone
              ? (showAllScores ? `✓ RD:${s.robotDesignScore} | IP:${s.innovationProjectScore}` : "✓ Đã cập nhật điểm")
              : "⏳ Chưa cập nhật"}
          </span>
        </div>
      `).join("")}
    </div>

    ${isLockedByOtherJudge ? `
      <div class="card" style="text-align: center; padding: 36px 24px;">
        <h3 style="color: var(--navy-800); margin-bottom: 8px;">✅ ${team.code} (${team.teamName}) – Đã Cập Nhật Điểm Thiết Kế Robot & Dự Án Đổi Mới</h3>
        <p style="font-size: 13.5px; color: var(--text-muted); max-width: 640px; margin: 0 auto;">
          Nhóm này đã được cập nhật điểm bởi <strong>${team.rubric.updatedBy}</strong> lúc ${team.rubric.updatedAt}.<br/>
          Theo quy định bảo mật của Ban Tổ Chức, <strong>thông tin điểm số và kết quả chỉ được hiển thị khi Quản trị viên (Admin) cho phép in & công bố kết quả</strong>.
        </p>
      </div>
    ` : `
      <div class="card">
        <!-- TỔNG HỢP ĐIỂM THUYẾT TRÌNH CỦA NHÓM ĐANG CHỌN -->
        <div style="display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; gap: 14px; margin-bottom: 18px; background: var(--bg-elevated); padding: 14px; border-radius: 8px; align-items: center;">
          <div>
            <label style="font-size: 12px; font-weight: 700; color: var(--text-secondary);">Tên Đội / Nhóm ${team.id}:</label>
            <input type="text" class="form-control" value="${team.teamName}" onchange="updateTeamNameInput(this.value)" />
          </div>
          <div class="progress-item" style="background: #fff;">
            <div class="lbl">⚙️ Thiết Kế Robot (${rdCount}/10 mục)</div>
            <div class="val">${sum.robotDesignScore} / 40 đ</div>
          </div>
          <div class="progress-item" style="background: #fff;">
            <div class="lbl">💡 Dự Án Đổi Mới (${ipCount}/10 mục)</div>
            <div class="val">${sum.innovationProjectScore} / 40 đ</div>
          </div>
          <div class="progress-item" style="background: var(--cv-light); border-color: #FECACA;">
            <div class="lbl" style="color: var(--cv-primary);">⚙♥ Giá Trị Cốt Lõi (Tự động)</div>
            <div class="val" style="color: var(--cv-primary);">${sum.coreValuesScore} / 40 đ</div>
          </div>
        </div>

        <!-- CHUYỂN TAB GIỮA THIẾT KẾ ROBOT VÀ DỰ ÁN ĐỔI MỚI -->
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 16px;">
          <div class="rule-tabs" style="margin-bottom: 0;">
            <button class="rule-tab ${isRD ? "active" : ""}" onclick="switchJudgeRubricTab('RD')">
              ⚙️ Thiết Kế Robot (${rdCount}/10)
            </button>
            <button class="rule-tab ${!isRD ? "active" : ""}" onclick="switchJudgeRubricTab('IP')">
              💡 Dự Án Đổi Mới (${ipCount}/10)
            </button>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn btn-outline" style="font-size: 12px; padding: 6px 12px;" onclick="openPrintCategoryModal('${isRD ? "RD" : "IP"}', 'SINGLE')">
              🖨️ In phiếu
            </button>
            <button class="btn btn-outline" style="font-size: 12px; padding: 6px 12px;" onclick="fillDefaultRubric3ForCurrentTeam()">
              ⚡ Điền nhanh mức 3đ
            </button>
          </div>
        </div>

        <!-- BẢNG RUBRIC TƯƠNG TÁC -->
        <table class="data-table">
          <thead>
            <tr>
              <th style="width: 80px; text-align: center;">Tiêu chí</th>
              <th style="width: 22%;">BẮT ĐẦU (1 điểm)</th>
              <th style="width: 22%;">PHÁT TRIỂN (2 điểm)</th>
              <th style="width: 22%;">HOÀN THÀNH (3 điểm)</th>
              <th>VƯỢT TRỘI (4 điểm)<br/><span style="font-weight: 400; font-size: 11px;">Đội/Nhóm đã vượt trội như thế nào?</span></th>
            </tr>
          </thead>
          <tbody>
            ${sections.map(sec => `
              <tr>
                <td colspan="5" class="rg-mission-group">${sec.section} – ${sec.desc}</td>
              </tr>
              ${sec.rows.map(r => {
                const curVal = Number(scoresMap[r.code]) || 0;
                const curNote = notesMap[r.code] || "";
                return `
                  <tr>
                    <td style="text-align: center;">
                      <span class="badge-code">${r.code}</span>
                      ${r.isCV ? `<div style="margin-top: 5px;"><span class="badge-cv" title="Tính điểm cho cả Giá Trị Cốt Lõi">⚙♥ CV</span></div>` : ""}
                    </td>
                    <td class="rubric-level-cell ${curVal === 1 ? "selected-lvl" : ""}" onclick="selectRubricLevel('${activeRubricTab}', '${r.code}', 1)">
                      <div class="rubric-radio-wrap">
                        <input type="radio" name="rub_${activeRubricTab}_${r.code}" ${curVal === 1 ? "checked" : ""} />
                        <span>${r.l1}</span>
                      </div>
                    </td>
                    <td class="rubric-level-cell ${curVal === 2 ? "selected-lvl" : ""}" onclick="selectRubricLevel('${activeRubricTab}', '${r.code}', 2)">
                      <div class="rubric-radio-wrap">
                        <input type="radio" name="rub_${activeRubricTab}_${r.code}" ${curVal === 2 ? "checked" : ""} />
                        <span>${r.l2}</span>
                      </div>
                    </td>
                    <td class="rubric-level-cell ${curVal === 3 ? "selected-lvl" : ""}" onclick="selectRubricLevel('${activeRubricTab}', '${r.code}', 3)">
                      <div class="rubric-radio-wrap">
                        <input type="radio" name="rub_${activeRubricTab}_${r.code}" ${curVal === 3 ? "checked" : ""} />
                        <span>${r.l3}</span>
                      </div>
                    </td>
                    <td class="rubric-level-cell ${curVal === 4 ? "selected-lvl" : ""}" onclick="selectRubricLevel('${activeRubricTab}', '${r.code}', 4)">
                      <div class="rubric-radio-wrap" style="margin-bottom: 6px;">
                        <input type="radio" name="rub_${activeRubricTab}_${r.code}" ${curVal === 4 ? "checked" : ""} />
                        <strong>Mức Vượt Trội (+4đ)</strong>
                      </div>
                      <input
                        type="text"
                        class="form-control"
                        style="font-size: 12px; padding: 6px 8px;"
                        placeholder="Ghi nhận xét ngắn gọn nếu đạt Vượt trội..."
                        value="${curNote}"
                        onclick="event.stopPropagation()"
                        onchange="updateRubricNote('${activeRubricTab}', '${r.code}', this.value)"
                      />
                    </td>
                  </tr>
                `;
              }).join("")}
            `).join("")}
          </tbody>
        </table>

        <!-- NÚT LƯU, IN PHIẾU HẠNG MỤC & XÓA RIÊNG NHÓM ĐANG PHỤ TRÁCH -->
        <div style="margin-top: 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; padding-top: 16px; border-top: 2px solid var(--bg-elevated);">
          <div style="font-size: 13px; color: var(--text-secondary);">
            ${team.rubric.completed
              ? `✅ <strong>Đã cập nhật điểm:</strong> Phụ trách chấm bởi <strong>${team.rubric.updatedBy}</strong> lúc ${team.rubric.updatedAt}`
              : `⚠️ Cần chấm đủ cả 2 tab: Thiết Kế Robot (${rdCount}/10) và Dự Án Đổi Mới (${ipCount}/10) trước khi bấm Lưu.`}
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            ${isRD ? `
              <button class="btn btn-outline" onclick="switchJudgeRubricTab('IP')">
                Sang Dự Án Đổi Mới ➡️
              </button>
            ` : `
              <button class="btn btn-outline" onclick="switchJudgeRubricTab('RD')">
                ⬅️ Về Thiết Kế Robot
              </button>
            `}
            <button class="btn btn-outline" onclick="openPrintCategoryModal('RUBRIC_BOTH', 'SINGLE')">
              🖨️ In 2 phiếu
            </button>
            <button class="btn btn-outline" onclick="exportExcelWorkbook('${isRD ? "RD" : "IP"}')">
              📊 Xuất Excel
            </button>
            ${canModifyThisTeam ? `
              <button class="btn btn-danger" style="padding: 10px 14px; font-size: 13px;" onclick="resetTeamRubric()">
                🗑️ Xóa điểm
              </button>
              <button class="btn btn-primary" style="padding: 10px 20px; font-size: 14px;" onclick="saveRubricTeam()">
                💾 Lưu điểm
              </button>
            ` : `
              <span class="status-badge status-locked" style="padding: 10px 14px; font-size: 13px;">
                🔒 Do ${team.rubric.updatedBy} phụ trách
              </span>
            `}
          </div>
        </div>
      </div>
    `}
  `;
}

// ============================================================================
// MÀN HÌNH CÔNG BỐ KẾT QUẢ CHÍNH THỨC & VINH DANH TOP 4 ĐỘI TUYỂN [BM06-TH]
// ============================================================================

function renderResultsView() {
  const st = getAllTeamsStatus();
  const isPublished = isResultPublishedByAdmin();
  const isAdmin = currentUser && currentUser.role === "ADMIN";

  if (!st.allCompleted || (!isPublished && !isAdmin)) {
    return `
      <div class="card" style="text-align: center; padding: 48px 24px;">
        <h2 style="color: var(--navy-800); margin-bottom: 12px;">🔒 Bảng Điểm Số & Kết Quả Chưa Được Công Bố</h2>
        <p style="color: var(--text-muted); margin-bottom: 20px; max-width: 640px; margin-left: auto; margin-right: auto;">
          ${!st.allCompleted
            ? `Hệ thống đang trong quá trình cập nhật điểm (${st.fullDoneCount}/8 nhóm đã cập nhật).`
            : `Tất cả 08/08 nhóm đã được cập nhật điểm. Kết quả sẽ được hiển thị khi Ban Tổ Chức chính thức công bố.`}
        </p>
        <button class="btn btn-navy" onclick="navigateTo('LANDING')">Về trang chủ</button>
      </div>
    `;
  }

  const ranked = getRankedTeams();
  const top4 = ranked.slice(0, 4);

  return `
    ${(isAdmin && !isPublished) ? `
      <div class="admin-publish-banner no-print">
        <div>
          <strong style="color: #FDE047; font-size: 14px;">🛡️ XEM TRƯỚC KẾT QUẢ (CHƯA CÔNG BỐ):</strong>
          <div style="font-size: 12.5px; color: #E2E8F0; margin-top: 2px;">
            Hiện tại giao diện bên ngoài chỉ hiển thị trạng thái <strong>"Đã cập nhật điểm"</strong>.
          </div>
        </div>
        <button class="btn btn-gold" onclick="toggleAdminPublishResults(true)">
          🔓 Công bố kết quả
        </button>
      </div>
    ` : ""}

    <!-- BANNER CÔNG BỐ KẾT QUẢ -->
    <div class="judge-header-bar" style="background: linear-gradient(135deg, var(--navy-900), var(--teal-700));">
      <div>
        <div style="font-size: 12px; color: #FDE047; font-weight: 800; letter-spacing: 0.05em;">
          TRƯỜNG THCS & THPT ĐINH THIỆN LÝ (LSTS) • MÙA GIẢI BIOGLOW • 30/10 (11h45 – 13h15)
        </div>
        <h2 style="font-size: 23px; font-weight: 900; margin-top: 2px;">
          🏆 CÔNG BỐ KẾT QUẢ CHÍNH THỨC & TOP 04 ĐỘI TUYỂN ĐƯỢC LỰA CHỌN
        </h2>
      </div>
      <div class="no-print" style="display: flex; gap: 8px; flex-wrap: wrap;">
        <button class="btn btn-gold" onclick="openPrintCategoryModal('SUMMARY', 'ALL')">
          🖨️ In tổng hợp
        </button>
        <button class="btn btn-outline-light" onclick="openPrintCategoryModal('RG', 'ALL')">
          🖨️ In Robot Game
        </button>
        <button class="btn btn-outline-light" onclick="openPrintCategoryModal('RD', 'ALL')">
          🖨️ In TK Robot
        </button>
        <button class="btn btn-outline-light" onclick="openPrintCategoryModal('IP', 'ALL')">
          🖨️ In Dự án
        </button>
        <button class="btn btn-outline-light" onclick="exportExcelWorkbook('ALL')">
          📊 Xuất Excel
        </button>
        <button class="btn btn-outline-light" onclick="navigateTo('LANDING')">
          🏠 Trang chủ
        </button>
      </div>
    </div>

    <!-- KHU VỰC 1: VINH DANH 04 NHÓM ĐƯỢC LỰA CHỌN (TOP 4 QUALIFIED TEAMS) -->
    <div style="margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between;">
      <h3 style="font-size: 18px; font-weight: 800; color: var(--navy-800);">
        🌟 DANH SÁCH 04 NHÓM CHÍNH THỨC ĐƯỢC LỰA CHỌN (THEO THỨ TỰ ĐIỂM TỪ CAO XUỐNG THẤP)
      </h3>
    </div>

    <div class="top4-grid">
      ${top4.map(t => `
        <div class="podium-card rank-${t.rank}">
          <div class="rank-ribbon">
            <span>🏅 HẠNG ${t.rank} CHUNG CUỘC</span>
            <span>•</span>
            <span>ĐƯỢC CHỌN</span>
          </div>
          <div class="podium-team-name">${t.teamName}</div>
          <div style="font-size: 12px; color: var(--text-muted); font-weight: 700;">Mã số: ${t.code}</div>

          <div class="podium-total-score">
            ${t.totalScore} <span style="font-size: 14px; font-weight: 600; color: var(--text-muted);">/ 230 đ</span>
          </div>

          <div class="podium-breakdown mono-num">
            <div>🤖 Robot Game: <strong>${t.robotGameScore}/110</strong></div>
            <div>⚙️ TK Robot: <strong>${t.robotDesignScore}/40</strong></div>
            <div>💡 Dự Án: <strong>${t.innovationProjectScore}/40</strong></div>
            <div>❤️ Core Values: <strong>${t.coreValuesScore}/40</strong></div>
            <div style="grid-column: span 2; color: var(--text-muted); margin-top: 2px;">
              ⏱️ Thời gian RG (${t.bestRunLabel}): <strong>${formatSeconds(t.robotGameTimeSec)}</strong>
            </div>
          </div>

          ${t.tieBreakReason ? `<div class="tie-badge">⚖️ ${t.tieBreakReason}</div>` : ""}
        </div>
      `).join("")}
    </div>

    <!-- KHU VỰC 2: BẢNG XẾP HẠNG TOÀN DIỆN CẢ 8 NHÓM [BM06-TH] -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3>📊 BẢNG TỔNG HỢP KẾT QUẢ THI ĐẤU TOÀN DIỆN 08 NHÓM [BM06-TH]</h3>
          <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">
            Xếp hạng tự động áp dụng quy tắc ưu tiên đồng điểm: (1) Điểm Robot Game cao hơn ➔ (2) Điểm Robot Design cao hơn ➔ (3) Điểm Core Values cao hơn ➔ (4) Thời gian hoàn thành Robot Game nhanh hơn.
          </p>
        </div>
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th style="width: 65px; text-align: center;">Hạng</th>
            <th style="width: 95px;">Mã Nhóm</th>
            <th>Tên Nhóm Dự Thi</th>
            <th style="text-align: center;">Robot Game<br/>(Max 110đ)</th>
            <th style="text-align: center;">Thiết Kế Robot<br/>(Max 40đ)</th>
            <th style="text-align: center;">Dự Án Đổi Mới<br/>(Max 40đ)</th>
            <th style="text-align: center;">Giá Trị Cốt Lõi<br/>(Max 40đ)</th>
            <th style="text-align: center;">Thời Gian RG<br/>(Tie-break #4)</th>
            <th style="text-align: center;">TỔNG ĐIỂM<br/>(Max 230đ)</th>
            <th style="text-align: center;">Kết Quả Xét Chọn</th>
          </tr>
        </thead>
        <tbody>
          ${ranked.map(t => `
            <tr style="${t.isQualified ? "background: #F0FDFA;" : ""}">
              <td class="mono-num" style="text-align: center; font-weight: 900; font-size: 15px; color: ${t.isQualified ? "var(--teal-700)" : "var(--text-muted)"};">
                #${t.rank}
              </td>
              <td><span class="badge-code">${t.code}</span></td>
              <td>
                <div style="font-weight: 800; color: var(--navy-800);">${t.teamName}</div>
                ${t.tieBreakReason ? `<div style="font-size: 11.5px; color: #B45309; font-weight: 700; margin-top: 3px;">⚖️ ${t.tieBreakReason}</div>` : ""}
              </td>
              <td class="mono-num" style="text-align: center; font-weight: 800; color: var(--navy-800);">
                ${t.robotGameScore} đ
                <div style="font-size: 11px; color: var(--text-muted); font-weight: 500;">(L1:${t.r1Score} | L2:${t.r2Score})</div>
              </td>
              <td class="mono-num" style="text-align: center; font-weight: 700;">${t.robotDesignScore} đ</td>
              <td class="mono-num" style="text-align: center; font-weight: 700;">${t.innovationProjectScore} đ</td>
              <td class="mono-num" style="text-align: center; font-weight: 700; color: var(--cv-primary);">
                ${t.coreValuesScore} đ
                <div style="font-size: 11px; color: var(--text-muted); font-weight: 500;">(RD:${t.rdCvTotal} + IP:${t.ipCvTotal})</div>
              </td>
              <td class="mono-num" style="text-align: center; font-size: 12.5px;">${formatSeconds(t.robotGameTimeSec)}</td>
              <td class="mono-num" style="text-align: center; font-size: 17px; font-weight: 900; color: var(--teal-700);">
                ${t.totalScore} đ
              </td>
              <td style="text-align: center;">
                ${t.isQualified
                  ? `<span class="qualified-pill">✓ TOP 4 ĐƯỢC CHỌN</span>`
                  : `<span class="not-qualified-pill">Hạng ${t.rank}</span>`}
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

// ============================================================================
// DỮ LIỆU DEMO (CÓ KỊCH BẢN ĐỒNG ĐIỂM TIE-BREAKER) & ĐỒNG BỘ JSON / CLOUD
// ============================================================================

function loadDemoScenario() {
  if (!currentUser || currentUser.role !== "ADMIN") {
    showToast("🔒 Chỉ Quản trị viên (Admin) mới có quyền nạp dữ liệu mẫu toàn hệ thống!");
    return;
  }
  const fresh = createInitialData();

  // Thiết lập kịch bản điểm thực tế cho 8 nhóm, cố tình tạo các cặp ĐỒNG TỔNG ĐIỂM
  // để thể hiện rõ 4 quy tắc ưu tiên Tie-breaker!
  const presets = [
    // Nhóm 1: Hạng 1 tuyệt đối (Tổng 210đ)
    {
      id: 1,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","M3_2","M3_3","EB_1"], t1: 145,
      r2: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","M3_2","M3_3","M3_4","EB_1","EB_2"], t2: 132, // 110đ
      rdVal: 3, rdExtra4: ["1.2","2.1","3.1","4.2","5.1"], // RD = 35đ, CV_RD = 19đ
      ipVal: 3, ipExtra4: ["1.2","2.2","3.1","5.1"],       // IP = 34đ, CV_IP = 19đ -> CV = 38đ -> Total = 110+35+34+38 = 217đ
    },
    // Nhóm 2 & Nhóm 3: CÙNG TỔNG ĐIỂM 185đ, phân định bằng Tie-break #1 (Điểm Robot Game cao hơn: 95đ vs 90đ)
    {
      id: 2,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","M3_2","M3_4","EB_1","EB_2"], t1: 150, // 20+30+35+10 = 95đ
      r2: ["M1_1","M1_2","M1_3","M2_1","M2_2","M3_1"], t2: 170,
      rdVal: 3, rdExtra4: [], // RD = 30đ, CV_RD = 15đ
      ipVal: 3, ipExtra4: [], // IP = 30đ, CV_IP = 15đ -> CV = 30đ -> Total = 95+30+30+30 = 185đ
    },
    {
      id: 3,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","M3_2","EB_1","EB_2"], t1: 140, // 20+30+30+10 = 90đ
      r2: ["M1_1","M1_2","M2_1","M2_2","M3_1"], t2: 160,
      rdVal: 3, rdExtra4: ["1.1","2.2","3.1","3.2","4.1"], // RD = 35đ (tăng ở các mục non-CV), CV_RD = 15đ
      ipVal: 3, ipExtra4: [], // IP = 30đ, CV_IP = 15đ -> CV = 30đ -> Total = 90+35+30+30 = 185đ
    },
    // Nhóm 4 & Nhóm 5 (Tranh vị trí thứ 4 vào Top 4!): CÙNG TỔNG ĐIỂM 176đ, CÙNG ROBOT GAME 80đ,
    // CÙNG ROBOT DESIGN 32đ, CÙNG CORE VALUES 32đ -> Phân định bằng Tie-break #4 (Thời gian Robot Game: 128s < 165s)
    {
      id: 4,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","M3_2"], t1: 128, // 20+30+30 = 80đ (128 giây)
      r2: ["M1_1","M1_2","M2_1","M2_2"], t2: 160,
      rdVal: 3, rdExtra4: ["1.1","1.2"], // RD = 32đ, CV_RD = 16đ
      ipVal: 3, ipExtra4: ["1.1","1.2"], // IP = 32đ, CV_IP = 16đ -> CV = 32đ -> Total = 80+32+32+32 = 176đ
    },
    {
      id: 5,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","M3_2"], t1: 165, // 20+30+30 = 80đ (165 giây)
      r2: ["M1_1","M1_2","M2_1","M2_2"], t2: 175,
      rdVal: 3, rdExtra4: ["1.1","1.2"], // RD = 32đ, CV_RD = 16đ
      ipVal: 3, ipExtra4: ["1.1","1.2"], // IP = 32đ, CV_IP = 16đ -> CV = 32đ -> Total = 80+32+32+32 = 176đ
    },
    // Nhóm 6: Tổng 164đ
    {
      id: 6,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","M3_1","EB_1"], t1: 155, // 70đ
      r2: ["M1_1","M1_2","M1_3","M2_1","M2_2"], t2: 180,
      rdVal: 3, rdExtra4: ["1.2"], // RD = 31đ, CV_RD = 16đ
      ipVal: 3, ipExtra4: ["1.2"], // IP = 31đ, CV_IP = 16đ -> CV = 32đ -> Total = 70+31+31+32 = 164đ
    },
    // Nhóm 7: Tổng 150đ
    {
      id: 7,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4","EB_1","EB_2"], t1: 172, // 60đ
      r2: ["M1_1","M1_2","M2_1","M2_2"], t2: 190,
      rdVal: 3, rdExtra4: [], // 30đ
      ipVal: 3, ipExtra4: [], // 30đ -> CV = 30đ -> Total = 150đ
    },
    // Nhóm 8: Tổng 140đ
    {
      id: 8,
      r1: ["M1_1","M1_2","M1_3","M1_4","M2_1","M2_2","M2_3","M2_4"], t1: 185, // 50đ
      r2: ["M1_1","M1_2","M2_1"], t2: 200,
      rdVal: 3, rdExtra4: [], // 30đ
      ipVal: 3, ipExtra4: [], // 30đ -> CV = 30đ -> Total = 140đ
    }
  ];

  presets.forEach(p => {
    const t = fresh.teams[p.id];
    t.robotGame.completed = true;
    t.robotGame.updatedBy = "Ban Giám Khảo RG";
    t.robotGame.updatedAt = new Date().toLocaleTimeString("vi-VN");
    t.robotGame.run1TimeSec = p.t1;
    t.robotGame.run2TimeSec = p.t2;
    p.r1.forEach(c => t.robotGame.run1[c] = true);
    p.r2.forEach(c => t.robotGame.run2[c] = true);

    t.rubric.completed = true;
    t.rubric.updatedBy = "Ban Giám Khảo Thuyết trình";
    t.rubric.updatedAt = new Date().toLocaleTimeString("vi-VN");
    RD_SECTIONS.forEach(s => s.rows.forEach(r => {
      t.rubric.rdScores[r.code] = p.rdExtra4.includes(r.code) ? 4 : p.rdVal;
      if (p.rdExtra4.includes(r.code)) t.rubric.rdNotes[r.code] = "Thiết kế cơ khí & giải pháp vượt trội";
    }));
    IP_SECTIONS.forEach(s => s.rows.forEach(r => {
      t.rubric.ipScores[r.code] = p.ipExtra4.includes(r.code) ? 4 : p.ipVal;
      if (p.ipExtra4.includes(r.code)) t.rubric.ipNotes[r.code] = "Nghiên cứu thực tiễn sâu sắc, mô hình sáng tạo";
    }));
  });

  appData = fresh;
  saveData(true);
  showToast("🎉 Đã nạp điểm mẫu 8 nhóm! Hiện đang ở chế độ 'Đã cập nhật điểm' — Bấm 'Cho Phép In & Công Bố Kết Quả' để mở công bố.");
  renderApp();
}

function resetAllScores() {
  if (!currentUser || currentUser.role !== "ADMIN") {
    showToast("🔒 Chỉ Quản trị viên (Admin) mới có quyền xóa toàn bộ dữ liệu của cả 8 nhóm!");
    return;
  }
  if (!confirm("Bạn có chắc chắn muốn xóa toàn bộ điểm đã nhập của cả 8 nhóm để làm lại từ đầu?")) return;
  appData = createInitialData();
  saveData(true);
  showToast("🗑️ Quản trị viên đã đặt lại toàn bộ dữ liệu của 8 nhóm về trạng thái ban đầu.");
  renderApp();
}

// ============================================================================
// IN PHIẾU ĐIỂM THEO TỪNG HẠNG MỤC THI (CHUẨN A4 LƯU TRỮ KẾT QUẢ)
// ============================================================================

function buildRgSheetHtml(teamId) {
  const team = appData.teams[teamId];
  const sum = computeTeamSummary(team);
  let rowsHtml = "";
  RG_CRITERIA.forEach(grp => {
    rowsHtml += `
      <tr>
        <td colspan="6" style="background: #E2E8F0; font-weight: 800; color: #0F2C59;">${grp.group}</td>
      </tr>
    `;
    grp.items.forEach(it => {
      const c1 = Boolean(team.robotGame.run1 && team.robotGame.run1[it.code]);
      const c2 = Boolean(team.robotGame.run2 && team.robotGame.run2[it.code]);
      rowsHtml += `
        <tr>
          <td style="text-align: center; font-weight: 700;">${it.label}</td>
          <td><strong>${it.title}</strong></td>
          <td style="font-size: 11px; color: #475569;">${it.cond}</td>
          <td style="text-align: center; font-weight: 700;">${it.pts} đ</td>
          <td style="text-align: center; font-weight: 700; color: ${c1 ? "#047857" : "#64748B"};">${c1 ? `✓ (+${it.pts}đ)` : "0 đ"}</td>
          <td style="text-align: center; font-weight: 700; color: ${c2 ? "#047857" : "#64748B"};">${c2 ? `✓ (+${it.pts}đ)` : "0 đ"}</td>
        </tr>
      `;
    });
  });

  return `
    <div class="a4-sheet">
      <div class="a4-header">
        <div>
          <div style="font-weight: 800; font-size: 13px; color: #0F2C59;">TRƯỜNG THCS & THPT ĐINH THIỆN LÝ (LSTS)</div>
          <div style="font-size: 11.5px; color: #334155;">Ban Tổ Chức Vòng 3 Tuyển Chọn Đội FLL Cấp Trường – Mùa Giải BIOGLOW</div>
        </div>
        <div style="text-align: right; font-size: 11.5px;">
          <div><strong>Mã biểu mẫu:</strong> [BM01-RG]</div>
          <div><strong>Phòng thi:</strong> Phòng A211</div>
        </div>
      </div>

      <div class="a4-title-block">
        <h2>PHIẾU CHẤM ĐIỂM HẠNG MỤC ROBOT GAME</h2>
        <div style="font-size: 12px; color: #475569;">Thời gian thi đấu: 11h45 đến 13h15 – Ngày 30 tháng 10 • Địa điểm: Phòng A211</div>
      </div>

      <div class="a4-meta-grid">
        <div><strong>Mã Nhóm:</strong> ${team.code}</div>
        <div><strong>Tên Đội / Nhóm:</strong> ${team.teamName}</div>
        <div><strong>Giám khảo chấm:</strong> ${team.robotGame.updatedBy || currentUser?.id || "................"}</div>
        <div><strong>Điểm Lượt 1:</strong> ${sum.r1Score}/110 đ (${formatSeconds(sum.t1)})</div>
        <div><strong>Điểm Lượt 2:</strong> ${sum.r2Score}/110 đ (${formatSeconds(sum.t2)})</div>
        <div><strong>ĐIỂM CHÍNH THỨC:</strong> <span style="font-size: 14px; font-weight: 900; color: #0F766E;">${sum.robotGameScore} / 110 đ</span> (${sum.bestRunLabel})</div>
      </div>

      <table class="a4-table">
        <thead>
          <tr>
            <th style="width: 55px; text-align: center;">Mã</th>
            <th>Nội dung Tiêu chí Nhiệm vụ</th>
            <th>Điều kiện Ghi nhận (Trạng thái cuối cùng)</th>
            <th style="width: 65px; text-align: center;">Điểm</th>
            <th style="width: 95px; text-align: center;">Lượt 1</th>
            <th style="width: 95px; text-align: center;">Lượt 2</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
          <tr style="background: #FEF3C7; font-weight: 800;">
            <td colspan="3" style="text-align: right;">TỔNG ĐIỂM TỪNG LƯỢT CHẠY:</td>
            <td style="text-align: center;">110 đ</td>
            <td style="text-align: center;">${sum.r1Score} / 110 đ</td>
            <td style="text-align: center;">${sum.r2Score} / 110 đ</td>
          </tr>
        </tbody>
      </table>

      <div class="a4-sign-grid">
        <div class="a4-sign-box">
          <strong>GIÁM KHẢO CHẤM THI</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Ký và ghi rõ họ tên)</span>
        </div>
        <div class="a4-sign-box">
          <strong>ĐẠI DIỆN NHÓM DỰ THI</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Xác nhận điểm & thời gian)</span>
        </div>
        <div class="a4-sign-box">
          <strong>BAN TỔ CHỨC / THƯ KÝ</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Kiểm tra & Lưu trữ)</span>
        </div>
      </div>
    </div>
  `;
}

function buildRubricSheetHtml(teamId, type) {
  const team = appData.teams[teamId];
  const sum = computeTeamSummary(team);
  const isRD = type === "RD";
  const sections = isRD ? RD_SECTIONS : IP_SECTIONS;
  const scoresMap = isRD ? team.rubric.rdScores : team.rubric.ipScores;
  const notesMap = isRD ? team.rubric.rdNotes : team.rubric.ipNotes;
  const formCode = isRD ? "[BM04-RD]" : "[BM05-IP]";
  const formTitle = isRD ? "PHIẾU ĐÁNH GIÁ HẠNG MỤC THIẾT KẾ ROBOT (ROBOT DESIGN)" : "PHIẾU ĐÁNH GIÁ HẠNG MỤC DỰ ÁN ĐỔI MỚI (INNOVATION PROJECT)";
  const catScore = isRD ? sum.robotDesignScore : sum.innovationProjectScore;
  const cvSubScore = isRD ? sum.rdCvTotal : sum.ipCvTotal;

  let rowsHtml = "";
  sections.forEach(sec => {
    rowsHtml += `
      <tr>
        <td colspan="6" style="background: #E2E8F0; font-weight: 800; color: #0F2C59;">${sec.section} – ${sec.desc}</td>
      </tr>
    `;
    sec.rows.forEach(r => {
      const val = Number(scoresMap[r.code]) || 0;
      const note = notesMap[r.code] || "";
      rowsHtml += `
        <tr>
          <td style="text-align: center; font-weight: 700;">
            ${r.code}
            ${r.isCV ? `<div style="font-size: 10px; color: #B91C1C; font-weight: 800;">⚙♥ CV</div>` : ""}
          </td>
          <td style="${val === 1 ? "background: #CCFBF1; font-weight: 700;" : ""}">${val === 1 ? "☑ " : "☐ "}${r.l1}</td>
          <td style="${val === 2 ? "background: #CCFBF1; font-weight: 700;" : ""}">${val === 2 ? "☑ " : "☐ "}${r.l2}</td>
          <td style="${val === 3 ? "background: #CCFBF1; font-weight: 700;" : ""}">${val === 3 ? "☑ " : "☐ "}${r.l3}</td>
          <td style="${val === 4 ? "background: #CCFBF1; font-weight: 700;" : ""}">
            ${val === 4 ? "☑ Vượt trội (4đ)" : "☐ Vượt trội (4đ)"}
            ${note ? `<div style="font-size: 10.5px; color: #0F2C59; margin-top: 2px;"><em>Ghi chú: ${note}</em></div>` : ""}
          </td>
          <td style="text-align: center; font-weight: 800; font-size: 13px;">${val > 0 ? `${val} đ` : "-"}</td>
        </tr>
      `;
    });
  });

  return `
    <div class="a4-sheet">
      <div class="a4-header">
        <div>
          <div style="font-weight: 800; font-size: 13px; color: #0F2C59;">TRƯỜNG THCS & THPT ĐINH THIỆN LÝ (LSTS)</div>
          <div style="font-size: 11.5px; color: #334155;">Ban Tổ Chức Vòng 3 Tuyển Chọn Đội FLL Cấp Trường – Mùa Giải BIOGLOW</div>
        </div>
        <div style="text-align: right; font-size: 11.5px;">
          <div><strong>Mã biểu mẫu:</strong> ${formCode}</div>
          <div><strong>Phòng thi:</strong> Phòng B217</div>
        </div>
      </div>

      <div class="a4-title-block">
        <h2>${formTitle}</h2>
        <div style="font-size: 12px; color: #475569;">Thời gian thi đấu: 11h45 đến 13h15 – Ngày 30 tháng 10 • Địa điểm: Phòng B217</div>
      </div>

      <div class="a4-meta-grid">
        <div><strong>Mã Nhóm:</strong> ${team.code}</div>
        <div><strong>Tên Đội / Nhóm:</strong> ${team.teamName}</div>
        <div><strong>Giám khảo chấm:</strong> ${team.rubric.updatedBy || currentUser?.id || "................"}</div>
        <div><strong>Tổng điểm hạng mục:</strong> <span style="font-weight: 900; color: #0F2C59;">${catScore} / 40 đ</span></div>
        <div><strong>Điểm trích xuất Core Values (5 mục ⚙♥ CV):</strong> <span style="font-weight: 900; color: #B91C1C;">${cvSubScore} / 20 đ</span></div>
        <div><strong>Tổng Core Values toàn đội (RD+IP):</strong> <strong>${sum.coreValuesScore} / 40 đ</strong></div>
      </div>

      <table class="a4-table">
        <thead>
          <tr>
            <th style="width: 55px; text-align: center;">Mục</th>
            <th style="width: 21%;">Bắt đầu (1đ)</th>
            <th style="width: 21%;">Phát triển (2đ)</th>
            <th style="width: 21%;">Hoàn thành (3đ)</th>
            <th>Vượt trội (4đ) & Nhận xét</th>
            <th style="width: 60px; text-align: center;">Điểm</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
          <tr style="background: #FEF3C7; font-weight: 800;">
            <td colspan="5" style="text-align: right;">TỔNG ĐIỂM HẠNG MỤC (${formCode}):</td>
            <td style="text-align: center; font-size: 13.5px;">${catScore} / 40 đ</td>
          </tr>
        </tbody>
      </table>

      <div class="a4-sign-grid">
        <div class="a4-sign-box">
          <strong>GIÁM KHẢO CHẤM THI</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Ký và ghi rõ họ tên)</span>
        </div>
        <div class="a4-sign-box">
          <strong>THƯ KÝ TỔNG HỢP</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Ký và ghi rõ họ tên)</span>
        </div>
        <div class="a4-sign-box">
          <strong>TRƯỞNG BAN GIÁM KHẢO</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Xác nhận lưu trữ)</span>
        </div>
      </div>
    </div>
  `;
}

function buildSummarySheetHtml() {
  const ranked = getRankedTeams();
  const rowsHtml = ranked.map(t => `
    <tr style="${t.isQualified ? "background: #F0FDFA; font-weight: 700;" : ""}">
      <td style="text-align: center; font-weight: 800;">#${t.rank}</td>
      <td style="text-align: center; font-weight: 700;">${t.code}</td>
      <td>
        <strong>${t.teamName}</strong>
        ${t.tieBreakReason ? `<div style="font-size: 10.5px; color: #B45309;">⚖️ ${t.tieBreakReason}</div>` : ""}
      </td>
      <td style="text-align: center;">${t.robotGameScore} / 110<br/><span style="font-size: 10px; color: #475569;">(L1:${t.r1Score} | L2:${t.r2Score})</span></td>
      <td style="text-align: center;">${t.robotDesignScore} / 40</td>
      <td style="text-align: center;">${t.innovationProjectScore} / 40</td>
      <td style="text-align: center;">${t.coreValuesScore} / 40<br/><span style="font-size: 10px; color: #475569;">(RD:${t.rdCvTotal}+IP:${t.ipCvTotal})</span></td>
      <td style="text-align: center;">${formatSeconds(t.robotGameTimeSec)}</td>
      <td style="text-align: center; font-weight: 900; font-size: 13.5px; color: #0F2C59;">${t.totalScore} / 230</td>
      <td style="text-align: center; font-weight: 800; color: ${t.isQualified ? "#047857" : "#64748B"};">
        ${t.isQualified ? "✓ ĐƯỢC CHỌN (TOP 4)" : `Hạng ${t.rank}`}
      </td>
    </tr>
  `).join("");

  return `
    <div class="a4-sheet">
      <div class="a4-header">
        <div>
          <div style="font-weight: 800; font-size: 13px; color: #0F2C59;">TRƯỜNG THCS & THPT ĐINH THIỆN LÝ (LSTS)</div>
          <div style="font-size: 11.5px; color: #334155;">Ban Tổ Chức Vòng 3 Tuyển Chọn Đội FLL Cấp Trường – Mùa Giải BIOGLOW</div>
        </div>
        <div style="text-align: right; font-size: 11.5px;">
          <div><strong>Mã biểu mẫu:</strong> [BM06-TH]</div>
          <div><strong>Ngày thi:</strong> 30/10 (11h45 – 13h15)</div>
        </div>
      </div>

      <div class="a4-title-block">
        <h2>BIÊN BẢN TỔNG HỢP ĐIỂM TOÀN DIỆN & CÔNG BỐ KẾT QUẢ CHÍNH THỨC</h2>
        <div style="font-size: 12px; color: #475569;">
          Địa điểm: Robot Game tại Phòng A211 • Thiết Kế Robot & Dự Án Đổi Mới tại Phòng B217
        </div>
      </div>

      <table class="a4-table">
        <thead>
          <tr>
            <th style="width: 45px; text-align: center;">Hạng</th>
            <th style="width: 75px; text-align: center;">Mã Nhóm</th>
            <th>Tên Đội / Nhóm Dự Thi</th>
            <th style="text-align: center;">Robot Game<br/>(110đ)</th>
            <th style="text-align: center;">TK Robot<br/>(40đ)</th>
            <th style="text-align: center;">Dự Án<br/>(40đ)</th>
            <th style="text-align: center;">Core Values<br/>(40đ)</th>
            <th style="text-align: center;">Thời Gian RG</th>
            <th style="text-align: center;">TỔNG ĐIỂM<br/>(230đ)</th>
            <th style="text-align: center;">Kết Quả</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>

      <div style="font-size: 11.5px; color: #334155; margin-bottom: 12px;">
        <strong>Quy tắc phân định đồng điểm (Tie-breaker):</strong> (1) Điểm Robot Game cao hơn ➔ (2) Điểm Thiết Kế Robot cao hơn ➔ (3) Điểm Core Values cao hơn ➔ (4) Thời gian hoàn thành Robot Game nhanh hơn.
      </div>

      <div class="a4-sign-grid">
        <div class="a4-sign-box">
          <strong>THƯ KÝ HỘI ĐỒNG</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Ký và ghi rõ họ tên)</span>
        </div>
        <div class="a4-sign-box">
          <strong>ĐẠI DIỆN BAN GIÁM KHẢO</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Ký và ghi rõ họ tên)</span>
        </div>
        <div class="a4-sign-box">
          <strong>TRƯỞNG BAN TỔ CHỨC (ADMIN)</strong><br/>
          <span style="font-size: 11px; color: #64748B;">(Ký duyệt công bố kết quả)</span>
        </div>
      </div>
    </div>
  `;
}

function openPrintCategoryModal(category, scope = "SINGLE") {
  if (!currentUser && !isResultPublishedByAdmin()) {
    showToast("🔒 Chỉ Ban Giám khảo hoặc Quản trị viên mới có quyền in phiếu điểm!");
    return;
  }

  // Kiểm tra quyền in bảng tổng hợp kết quả chung cuộc
  if (category === "SUMMARY") {
    const st = getAllTeamsStatus();
    if (!st.allCompleted) {
      showToast(`⚠️ Chưa thể in Biên bản kết quả chung cuộc vì mới cập nhật ${st.fullDoneCount}/8 nhóm!`);
      return;
    }
    if (!isResultPublishedByAdmin()) {
      if (currentUser && currentUser.role === "ADMIN") {
        // Khi Quản trị viên bấm In Biên bản kết quả, tự động bật cho phép công bố kết quả theo đúng yêu cầu
        appData.allowPrintAndPublish = true;
        saveData(true);
        renderApp();
        showToast("🔓 Quản trị viên đã duyệt In kết quả – Hệ thống đã mở công bố kết quả chính thức!");
      } else {
        showToast("🔒 Chỉ khi Quản trị viên (Admin) cho phép In & Công bố thì mới có thể in Biên bản kết quả!");
        return;
      }
    }
  }

  const teamIds = scope === "ALL" ? [1, 2, 3, 4, 5, 6, 7, 8] : [selectedTeamId];
  let html = "";
  let title = "🖨️ Xem Trước & In Phiếu Điểm Hạng Mục";

  if (category === "RG") {
    title = `🖨️ Phiếu Chấm Điểm Robot Game [BM01-RG] (${scope === "ALL" ? "Tất cả 8 Nhóm" : `Nhóm ${selectedTeamId}`})`;
    html = teamIds.map(id => buildRgSheetHtml(id)).join("");
  } else if (category === "RD") {
    title = `🖨️ Phiếu Đánh Giá Thiết Kế Robot [BM04-RD] (${scope === "ALL" ? "Tất cả 8 Nhóm" : `Nhóm ${selectedTeamId}`})`;
    html = teamIds.map(id => buildRubricSheetHtml(id, "RD")).join("");
  } else if (category === "IP") {
    title = `🖨️ Phiếu Đánh Giá Dự Án Đổi Mới [BM05-IP] (${scope === "ALL" ? "Tất cả 8 Nhóm" : `Nhóm ${selectedTeamId}`})`;
    html = teamIds.map(id => buildRubricSheetHtml(id, "IP")).join("");
  } else if (category === "RUBRIC_BOTH") {
    title = `🖨️ Bộ Phiếu Thiết Kế Robot & Dự Án Đổi Mới (Nhóm ${selectedTeamId})`;
    html = teamIds.map(id => buildRubricSheetHtml(id, "RD") + buildRubricSheetHtml(id, "IP")).join("");
  } else if (category === "SUMMARY") {
    title = "🖨️ Biên Bản Tổng Hợp Kết Quả & Xếp Hạng 08 Nhóm [BM06-TH]";
    html = buildSummarySheetHtml();
  }

  const modal = document.getElementById("printModalOverlay");
  const preview = document.getElementById("printPreviewContent");
  const printContainer = document.getElementById("printableSheetContainer");
  const titleEl = document.getElementById("printModalTitle");

  if (titleEl) titleEl.textContent = title;
  if (preview) preview.innerHTML = html;
  if (printContainer) printContainer.innerHTML = html;
  if (modal) modal.style.display = "flex";
}

function closePrintModal() {
  const modal = document.getElementById("printModalOverlay");
  if (modal) modal.style.display = "none";
  document.body.classList.remove("printing-custom-sheet");
}

function executeSheetPrint() {
  document.body.classList.add("printing-custom-sheet");
  window.print();
  setTimeout(() => {
    document.body.classList.remove("printing-custom-sheet");
  }, 600);
}

// ============================================================================
// XUẤT FILE EXCEL (.XLS NHIỀU SHEET) & ĐỒNG BỘ FILE EXCEL TRỰC TUYẾN BẢO MẬT
// ============================================================================

function escapeXml(unsafe) {
  return String(unsafe ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function buildWorksheetXml(sheetName, rows) {
  const rowsXml = rows.map((row, rIdx) => {
    const cellsXml = row.map(cell => {
      const isNum = typeof cell === "number" && !isNaN(cell);
      const type = isNum ? "Number" : "String";
      const styleId = rIdx === 0 ? "sHeader" : (isNum ? "sNum" : "sCell");
      return `<Cell ss:StyleID="${styleId}"><Data ss:Type="${type}">${escapeXml(cell)}</Data></Cell>`;
    }).join("");
    return `<Row ss:AutoFitHeight="1">${cellsXml}</Row>`;
  }).join("");

  return `
    <Worksheet ss:Name="${escapeXml(sheetName)}">
      <Table>${rowsXml}</Table>
    </Worksheet>
  `;
}

function generateExcelSheetsData() {
  const ranked = getRankedTeams();

  // Sheet 1: Tổng hợp 8 nhóm (Chỉ ghi các nhóm đã có điểm cập nhật; khi xóa điểm thì dòng đó biến mất hoàn toàn)
  const sheetSummary = [
    ["Hạng", "Mã Nhóm", "Tên Nhóm Dự Thi", "Robot Game (110đ)", "Thiết Kế Robot (40đ)", "Dự Án Đổi Mới (40đ)", "Core Values (40đ)", "Thời Gian RG (Giây)", "Tổng Điểm (230đ)", "Kết Quả Xét Chọn", "Ghi Chú Phân Định Đồng Điểm"]
  ];
  const activeRanked = ranked.filter(t => t.isRgDone || t.isRubricDone);
  activeRanked.forEach((t, idx) => {
    const displayRank = idx + 1;
    sheetSummary.push([
      t.isFullyDone ? displayRank : "",
      t.code,
      t.teamName,
      t.isRgDone ? t.robotGameScore : "",
      t.isRubricDone ? t.robotDesignScore : "",
      t.isRubricDone ? t.innovationProjectScore : "",
      t.isRubricDone ? t.coreValuesScore : "",
      t.isRgDone ? t.robotGameTimeSec : "",
      (t.isRgDone || t.isRubricDone) ? t.totalScore : "",
      t.isFullyDone ? (displayRank <= 4 ? "TOP 4 ĐƯỢC CHỌN" : `Hạng ${displayRank}`) : "Đang cập nhật",
      t.isFullyDone ? (t.tieBreakReason || "Không") : ""
    ]);
  });

  // Sheet 2: Chi tiết Robot Game - Phòng A211 (Chỉ ghi các nhóm đã chấm Robot Game)
  const rgCriteriaCodes = [];
  RG_CRITERIA.forEach(g => g.items.forEach(it => rgCriteriaCodes.push(it)));
  const sheetRG = [
    ["Mã Nhóm", "Tên Nhóm", "Trạng Thái", "Giám Khảo", "Điểm Lượt 1", "TG Lượt 1 (s)", "Điểm Lượt 2", "TG Lượt 2 (s)", "Điểm Chính Thức (Max 110)", "TG Chính Thức (s)", ...rgCriteriaCodes.map(c => `${c.label} (${c.pts}đ)`)]
  ];
  for (let i = 1; i <= 8; i++) {
    const team = appData.teams[i];
    if (!team.robotGame.completed) continue;
    const sum = computeTeamSummary(team);
    const bestRunObj = sum.bestRunLabel === "Lượt 1" ? (team.robotGame.run1 || {}) : (team.robotGame.run2 || {});
    sheetRG.push([
      team.code,
      team.teamName,
      "Đã cập nhật",
      team.robotGame.updatedBy || "",
      sum.r1Score,
      sum.t1,
      sum.r2Score,
      sum.t2,
      sum.robotGameScore,
      sum.robotGameTimeSec,
      ...rgCriteriaCodes.map(c => bestRunObj[c.code] ? c.pts : 0)
    ]);
  }

  // Sheet 3: Chi tiết Thiết kế Robot - Phòng B217 (Chỉ ghi các nhóm đã chấm Thuyết trình)
  const rdCodes = [];
  RD_SECTIONS.forEach(s => s.rows.forEach(r => rdCodes.push(r)));
  const sheetRD = [
    ["Mã Nhóm", "Tên Nhóm", "Trạng Thái", "Giám Khảo", ...rdCodes.map(r => `Mục ${r.code}${r.isCV ? " (CV)" : ""}`), "Tổng Thiết Kế Robot (40đ)", "Điểm CV từ RD (20đ)"]
  ];
  for (let i = 1; i <= 8; i++) {
    const team = appData.teams[i];
    if (!team.rubric.completed) continue;
    const sum = computeTeamSummary(team);
    sheetRD.push([
      team.code,
      team.teamName,
      "Đã cập nhật",
      team.rubric.updatedBy || "",
      ...rdCodes.map(r => Number(team.rubric.rdScores[r.code]) || 0),
      sum.robotDesignScore,
      sum.rdCvTotal
    ]);
  }

  // Sheet 4: Chi tiết Dự án Đổi mới - Phòng B217 (Chỉ ghi các nhóm đã chấm Thuyết trình)
  const ipCodes = [];
  IP_SECTIONS.forEach(s => s.rows.forEach(r => ipCodes.push(r)));
  const sheetIP = [
    ["Mã Nhóm", "Tên Nhóm", "Trạng Thái", "Giám Khảo", ...ipCodes.map(r => `Mục ${r.code}${r.isCV ? " (CV)" : ""}`), "Tổng Dự Án Đổi Mới (40đ)", "Điểm CV từ IP (20đ)"]
  ];
  for (let i = 1; i <= 8; i++) {
    const team = appData.teams[i];
    if (!team.rubric.completed) continue;
    const sum = computeTeamSummary(team);
    sheetIP.push([
      team.code,
      team.teamName,
      "Đã cập nhật",
      team.rubric.updatedBy || "",
      ...ipCodes.map(r => Number(team.rubric.ipScores[r.code]) || 0),
      sum.innovationProjectScore,
      sum.ipCvTotal
    ]);
  }

  function padSheetRows(rows) {
    const maxCols = rows.reduce((max, r) => Math.max(max, r.length), 0);
    return rows.map(r => {
      if (r.length >= maxCols) return r;
      return [...r, ...Array(maxCols - r.length).fill("")];
    });
  }

  return {
    sheetSummary: padSheetRows(sheetSummary),
    sheetRG: padSheetRows(sheetRG),
    sheetRD: padSheetRows(sheetRD),
    sheetIP: padSheetRows(sheetIP)
  };
}

function exportExcelWorkbook(categoryFilter = "ALL") {
  if (!currentUser) {
    showToast("🔒 Chỉ Ban Giám khảo và Quản trị viên mới có quyền xuất file Excel lưu trữ!");
    return;
  }

  const { sheetSummary, sheetRG, sheetRD, sheetIP } = generateExcelSheetsData();
  let worksheetsXml = "";
  let fileSuffix = "Toan_Bo_4_Sheet";

  if (categoryFilter === "RG") {
    worksheetsXml = buildWorksheetXml("Robot_Game_A211", sheetRG);
    fileSuffix = "Robot_Game_A211";
  } else if (categoryFilter === "RD") {
    worksheetsXml = buildWorksheetXml("Thiet_Ke_Robot_B217", sheetRD);
    fileSuffix = "Thiet_Ke_Robot_B217";
  } else if (categoryFilter === "IP") {
    worksheetsXml = buildWorksheetXml("Du_An_Doi_Moi_B217", sheetIP);
    fileSuffix = "Du_An_Doi_Moi_B217";
  } else {
    worksheetsXml =
      buildWorksheetXml("1_Tong_Hop_8_Nhom", sheetSummary) +
      buildWorksheetXml("2_Robot_Game_A211", sheetRG) +
      buildWorksheetXml("3_Thiet_Ke_Robot_B217", sheetRD) +
      buildWorksheetXml("4_Du_An_Doi_Moi_B217", sheetIP);
  }

  const workbookXml = `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
  <Styles>
    <Style ss:ID="sTitle">
      <Font ss:Bold="1" ss:Size="12" ss:Color="#0F2C59"/>
    </Style>
    <Style ss:ID="sHeader">
      <Font ss:Bold="1" ss:Color="#FFFFFF"/>
      <Interior ss:Color="#0F2C59" ss:Pattern="Solid"/>
    </Style>
    <Style ss:ID="sCell">
      <Borders>
        <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#CBD5E1"/>
        <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#CBD5E1"/>
      </Borders>
    </Style>
    <Style ss:ID="sNum">
      <Alignment ss:Horizontal="Center"/>
      <Font ss:Bold="1"/>
      <Borders>
        <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#CBD5E1"/>
        <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1" ss:Color="#CBD5E1"/>
      </Borders>
    </Style>
  </Styles>
  ${worksheetsXml}
</Workbook>`;

  const blob = new Blob([workbookXml], { type: "application/vnd.ms-excel;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `FLL_LSTS_BIOGLOW_${fileSuffix}_${new Date().toISOString().slice(0, 10)}.xls`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`📊 Đã xuất File Excel (${fileSuffix}) thành công!`);
}

function exportJsonData() {
  if (!currentUser) return;
  const blob = new Blob([JSON.stringify(appData, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `FLL_LSTS_BIOGLOW_Scores_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("⬇️ Đã tải xuống file sao lưu dữ liệu JSON!");
}

function importJsonData(event) {
  if (!currentUser || currentUser.role !== "ADMIN") {
    showToast("🔒 Chỉ Quản trị viên (Admin) mới có quyền nhập đè toàn bộ dữ liệu hệ thống!");
    return;
  }
  const file = event.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      if (parsed && parsed.teams) {
        if (typeof parsed.allowPrintAndPublish !== "boolean") {
          parsed.allowPrintAndPublish = false;
        }
        appData = parsed;
        saveData(true);
        showToast("⬆️ Đã nhập dữ liệu điểm từ file JSON thành công!");
        renderApp();
      } else {
        showToast("⚠️ File JSON không đúng cấu trúc hệ thống chấm FLL!");
      }
    } catch (err) {
      showToast("⚠️ Lỗi đọc file JSON!");
    }
  };
  reader.readAsText(file);
}

// ============================================================================
// ĐỒNG BỘ FILE EXCEL TRỰC TUYẾN BẢO MẬT (GOOGLE SHEETS / EXCEL ONLINE / CLOUD)
// ============================================================================

// Địa chỉ Web App Google Apps Script dùng chung cho mọi máy giáo viên.
// Dán địa chỉ dạng https://script.google.com/macros/s/.../exec vào giữa 2 dấu nháy.
const DEFAULT_CLOUD_URL = "https://script.google.com/macros/s/AKfycbwe12ietgw1-fPs3ZV5PoeyZxtXJIw25iHNHXrDPmmGuXLeNr5v4S3iarAHcxFJ-DkqGA/exec";

function getCloudCfg() {
  let cfg = {};
  try {
    const raw = localStorage.getItem(CLOUD_CFG_KEY);
    if (raw) cfg = decodeSecureStorage(raw, "EXCEL_CLOUD_CFG") || {};
  } catch {
    cfg = {};
  }
  if (!cfg.url && DEFAULT_CLOUD_URL) cfg.url = DEFAULT_CLOUD_URL;
  return cfg;
}

function toggleCloudModal() {
  const el = document.getElementById("cloudConfigPanel");
  if (el) {
    el.style.display = el.style.display === "none" ? "block" : "none";
  }
}

function saveCloudCfg() {
  if (!currentUser) return;
  const url = (document.getElementById("cloudUrlInput")?.value || "").trim();
  localStorage.setItem(CLOUD_CFG_KEY, encodeSecureStorage({ url }, "EXCEL_CLOUD_CFG"));
  showToast("🔒 Đã mã hóa và lưu liên kết Máy chủ Google Apps Script!");
  pushToCloudIfConfigured(true);
  renderApp();
}

function generateStretchedRecordSnippet() {
  if (!currentUser || currentUser.role !== "ADMIN") return;
  const u = (document.getElementById("genAccUser")?.value || "").trim().toUpperCase();
  const p = (document.getElementById("genAccPass")?.value || "").trim();
  const r = (document.getElementById("genAccRole")?.value || "RG").trim();
  if (!u || p.length < 10) {
    showToast("⚠️ Vui lòng nhập tên tài khoản và mật khẩu tối thiểu 10–12 ký tự (kết hợp Hoa, thường, số, ký tự đặc biệt)!");
    return;
  }
  const uHash = stretchHash(`USR:${u}`);
  const pHash = stretchHash(`PWD:${u}:${p}`);
  const snippet = `{ userHash: "${uHash}", passHash: "${pHash}", role: "${r}" }`;
  const outEl = document.getElementById("genAccResult");
  if (outEl) {
    outEl.textContent = `Đã tạo (20.000 vòng SHA-256): ${snippet}`;
  }
  navigator.clipboard.writeText(snippet).then(() => {
    showToast("📋 Đã tạo và copy bản ghi mã băm 20.000 vòng vào bộ nhớ tạm!");
  }).catch(() => {});
}

async function pushToCloudIfConfigured(showFeedback = false) {
  const cfg = getCloudCfg();
  if (!currentUser) return;
  if (!cfg.url) {
    showToast("⚠️ Máy này chưa kết nối Google Sheets nên điểm CHƯA được đồng bộ. Vui lòng báo Quản trị viên!");
    return;
  }
  try {
    const isGoogleScript = cfg.url.includes("script.google.com");

    // Nếu là giám khảo (RG hoặc RUBRIC), tải dữ liệu mới nhất từ Server trước để giữ nguyên điểm các nhóm khác trước khi xuất 4 Sheet
    if (isGoogleScript && currentUser.role !== "ADMIN") {
      try {
        const preRes = await fetch(cfg.url, {
          method: "POST",
          headers: { "Content-Type": "text/plain;charset=utf-8" },
          body: JSON.stringify({
            action: "FETCH_DATA",
            uHash: currentUser.uHash,
            pHash: currentUser.pHash
          })
        });
        const preJson = await preRes.json();
        if (preJson && preJson.ok && preJson.appData && preJson.appData.teams) {
          const srv = preJson.appData;
          const myTeam = JSON.parse(JSON.stringify(appData.teams[selectedTeamId]));
          appData.allowPrintAndPublish = Boolean(srv.allowPrintAndPublish);
          for (let tid = 1; tid <= 8; tid++) {
            if (srv.teams[tid]) {
              if (tid === selectedTeamId) {
                if (currentUser.role === "RG") {
                  appData.teams[tid].rubric = srv.teams[tid].rubric || appData.teams[tid].rubric;
                  appData.teams[tid].robotGame = myTeam.robotGame;
                } else if (currentUser.role === "RUBRIC") {
                  appData.teams[tid].robotGame = srv.teams[tid].robotGame || appData.teams[tid].robotGame;
                  appData.teams[tid].rubric = myTeam.rubric;
                }
              } else {
                appData.teams[tid] = srv.teams[tid];
              }
            }
          }
          saveData(false);
        }
      } catch (preErr) {
        console.warn("Pre-fetch merge skipped:", preErr);
      }
    }

    const sheetsData = generateExcelSheetsData();
    const payload = {
      action: "UPDATE_SCORES",
      uHash: currentUser.uHash,
      pHash: currentUser.pHash,
      teamId: selectedTeamId,
      updatedBy: currentUser.id,
      updatedAt: new Date().toISOString(),
      appData,
      sheets: sheetsData
    };

    if (isGoogleScript) {
      const res = await fetch(cfg.url, {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify(payload)
      });
      const json = await res.json();
      if (json && json.ok) {
        if (json.appData && json.appData.teams) {
          appData = json.appData;
          saveData(false);
          renderApp();
        }
        if (showFeedback) {
          showToast("☁️ Đã đồng bộ dữ liệu lên Google Sheets thành công!");
        }
      } else {
        showToast(`⚠️ Không thể đồng bộ: ${json?.error || "Sai phân quyền hoặc thông tin xác thực"}`);
      }
    } else {
      await fetch(cfg.url, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (showFeedback) {
        showToast("☁️ Đã đồng bộ dữ liệu trực tuyến thành công!");
      }
    }
  } catch (e) {
    console.warn("Online Excel sync warning:", e);
    if (showFeedback) {
      showToast("⚠️ Không thể kết nối tới Google Sheets. Vui lòng kiểm tra lại liên kết!");
    }
  }
}

async function pullFromCloud(silent = false) {
  const cfg = getCloudCfg();
  if (!cfg.url) {
    if (!silent && currentUser) showToast("⚠️ Vui lòng nhập liên kết Web App Google Apps Script trước khi tải!");
    return;
  }
  try {
    const isGoogleScript = cfg.url.includes("script.google.com");
    let res;
    if (isGoogleScript && currentUser && currentUser.uHash && currentUser.pHash) {
      // Nếu đã đăng nhập, gửi kèm uHash và pHash qua doPost để Server trả về dữ liệu theo đúng phân quyền
      res = await fetch(cfg.url, {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({
          action: "FETCH_DATA",
          uHash: currentUser.uHash,
          pHash: currentUser.pHash
        })
      });
    } else {
      res = await fetch(cfg.url);
    }

    const json = await res.json();
    const record = json.appData || (json.record && json.record.appData) || json.record || json;
    if (record && record.teams) {
      if (typeof record.allowPrintAndPublish !== "boolean") {
        record.allowPrintAndPublish = false;
      }
      cleanEmptyTeamStates(record);
      appData = record;
      saveData(false);
      if (!silent && currentUser) {
        showToast("☁️ Đã tải và đồng bộ dữ liệu mới nhất từ Google Sheets!");
      }
      renderApp();
    } else {
      if (!silent && currentUser) showToast("⚠️ Server chưa có dữ liệu hoặc từ chối truy cập!");
    }
  } catch (e) {
    if (!silent && currentUser) showToast("⚠️ Không thể tải dữ liệu từ Google Sheets!");
  }
}

function copyAppsScriptTemplate() {
  if (!currentUser || currentUser.role !== "ADMIN") return;
  const authRecordsJson = JSON.stringify(OFFLINE_AUTH_RECORDS, null, 2);
  const scriptCode = `// ============================================================================
// GOOGLE APPS SCRIPT BACKEND - XÁC THỰC TÀI KHOẢN, PHÂN QUYỀN (RBAC) & ĐỒNG BỘ EXCEL
// Mã nguồn này chạy ẩn trên Google Cloud (Học sinh KHÔNG THỂ xem hay dịch ngược).
// Hướng dẫn: Mở Google Sheets của BTC -> Tiện ích mở rộng -> Apps Script
// Dán toàn bộ mã này -> Triển khai (Deploy) -> Ứng dụng web (Web App) -> Bất kỳ ai
// ============================================================================

// Danh sách uHash & pHash (đã qua 20.000 vòng SHA-256 Key Stretching) lưu bí mật trên Google Cloud
const SERVER_AUTH_RECORDS = ${authRecordsJson};

function verifyAccount(uHash, pHash) {
  if (!uHash || !pHash) return null;
  for (var i = 0; i < SERVER_AUTH_RECORDS.length; i++) {
    var r = SERVER_AUTH_RECORDS[i];
    if (r.userHash === uHash && r.passHash === pHash) {
      return r;
    }
  }
  return null;
}

function writeSheetTable(ss, name, rows) {
  if (!rows || !rows.length) return;
  var maxCols = 0;
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].length > maxCols) maxCols = rows[i].length;
  }
  var normalized = [];
  for (var r = 0; r < rows.length; r++) {
    var rowCopy = rows[r].slice();
    while (rowCopy.length < maxCols) rowCopy.push("");
    normalized.push(rowCopy);
  }
  var sheet = ss.getSheetByName(name);
  if (!sheet) sheet = ss.insertSheet(name);
  sheet.clearContents();
  sheet.getRange(1, 1, normalized.length, maxCols).setValues(normalized);
}

// Ẩn toàn bộ điểm số đối với người dùng công khai khi Admin chưa cho phép In & Công bố
function sanitizeForPublic(data) {
  if (!data || !data.teams) return {};
  if (data.allowPrintAndPublish === true) return data;
  var copy = JSON.parse(JSON.stringify(data));
  for (var id in copy.teams) {
    var t = copy.teams[id];
    if (t.robotGame) {
      t.robotGame.run1 = {};
      t.robotGame.run2 = {};
      t.robotGame.run1TimeSec = 240;
      t.robotGame.run2TimeSec = 240;
    }
    if (t.rubric) {
      t.rubric.rdScores = {};
      t.rubric.ipScores = {};
      t.rubric.rdNotes = {};
      t.rubric.ipNotes = {};
    }
  }
  return copy;
}

function doPost(e) {
  try {
    var body = JSON.parse(e.postData.contents || "{}");
    var acc = verifyAccount(body.uHash, body.pHash);
    if (!acc) {
      return ContentService.createTextOutput(JSON.stringify({
        ok: false,
        error: "INVALID_CREDENTIALS"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    var props = PropertiesService.getScriptProperties();
    var rawSaved = props.getProperty("FLL_APP_DATA");
    var serverData = rawSaved ? JSON.parse(rawSaved) : null;

    // 1. Nếu chỉ xác thực đăng nhập hoặc tải dữ liệu đã xác thực
    if (body.action === "VERIFY_LOGIN" || body.action === "FETCH_DATA") {
      return ContentService.createTextOutput(JSON.stringify({
        ok: true,
        role: acc.role,
        appData: serverData
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // 2. Nếu ghi bảng 4 Sheet đã hợp nhất từ toàn bộ các giám khảo
    if (body.action === "WRITE_MERGED_SHEETS" && body.sheets) {
      var ssMerged = SpreadsheetApp.getActiveSpreadsheet();
      writeSheetTable(ssMerged, "1_Tong_Hop_8_Nhom", body.sheets.sheetSummary);
      writeSheetTable(ssMerged, "2_Robot_Game_A211", body.sheets.sheetRG);
      writeSheetTable(ssMerged, "3_Thiet_Ke_Robot_B217", body.sheets.sheetRD);
      writeSheetTable(ssMerged, "4_Du_An_Doi_Moi_B217", body.sheets.sheetIP);
      return ContentService.createTextOutput(JSON.stringify({ ok: true })).setMimeType(ContentService.MimeType.JSON);
    }

    // 3. Xử lý cập nhật hoặc xóa điểm có kiểm soát phân quyền chặt chẽ trên Server (RBAC)
    var incoming = body.appData;
    if (!incoming || !incoming.teams) {
      return ContentService.createTextOutput(JSON.stringify({ ok: false, error: "INVALID_PAYLOAD" })).setMimeType(ContentService.MimeType.JSON);
    }

    var targetTid = Number(body.teamId) || 0;

    if (!serverData || !serverData.teams) {
      serverData = incoming;
      if (acc.role !== "ADMIN") {
        serverData.allowPrintAndPublish = false;
      }
    } else if (acc.role === "ADMIN") {
      // Chỉ tài khoản ADMIN mới được phép thay đổi allowPrintAndPublish hoặc ghi đè/xóa toàn bộ dữ liệu
      serverData = incoming;
    } else if (acc.role === "RG") {
      // Tài khoản RG: Chỉ cập nhật hoặc xóa robotGame của đúng nhóm đang thao tác (targetTid), giữ nguyên các nhóm khác và rubric
      var startRg = (targetTid >= 1 && targetTid <= 8) ? targetTid : 1;
      var endRg = (targetTid >= 1 && targetTid <= 8) ? targetTid : 8;
      for (var tid = startRg; tid <= endRg; tid++) {
        if (incoming.teams[tid] && serverData.teams[tid]) {
          var curRg = serverData.teams[tid].robotGame || {};
          var nextRg = incoming.teams[tid].robotGame || {};
          if (!curRg.completed || !curRg.updatedBy || curRg.updatedBy === body.updatedBy) {
            serverData.teams[tid].robotGame = nextRg;
            serverData.teams[tid].teamName = incoming.teams[tid].teamName || serverData.teams[tid].teamName;
          }
        }
      }
    } else if (acc.role === "RUBRIC") {
      // Tài khoản RUBRIC: Chỉ cập nhật hoặc xóa rubric của đúng nhóm đang thao tác (targetTid), giữ nguyên các nhóm khác và robotGame
      var startRub = (targetTid >= 1 && targetTid <= 8) ? targetTid : 1;
      var endRub = (targetTid >= 1 && targetTid <= 8) ? targetTid : 8;
      for (var tid2 = startRub; tid2 <= endRub; tid2++) {
        if (incoming.teams[tid2] && serverData.teams[tid2]) {
          var curRub = serverData.teams[tid2].rubric || {};
          var nextRub = incoming.teams[tid2].rubric || {};
          if (!curRub.completed || !curRub.updatedBy || curRub.updatedBy === body.updatedBy) {
            serverData.teams[tid2].rubric = nextRub;
            serverData.teams[tid2].teamName = incoming.teams[tid2].teamName || serverData.teams[tid2].teamName;
          }
        }
      }
    }

    serverData.lastModified = new Date().toISOString();
    props.setProperty("FLL_APP_DATA", JSON.stringify(serverData));

    // Cập nhật 4 Sheet trên Google Sheets
    if (body.sheets) {
      var ss = SpreadsheetApp.getActiveSpreadsheet();
      if (acc.role === "ADMIN" || acc.role === "RG") {
        writeSheetTable(ss, "2_Robot_Game_A211", body.sheets.sheetRG);
      }
      if (acc.role === "ADMIN" || acc.role === "RUBRIC") {
        writeSheetTable(ss, "3_Thiet_Ke_Robot_B217", body.sheets.sheetRD);
        writeSheetTable(ss, "4_Du_An_Doi_Moi_B217", body.sheets.sheetIP);
      }
      writeSheetTable(ss, "1_Tong_Hop_8_Nhom", body.sheets.sheetSummary);
    }

    return ContentService.createTextOutput(JSON.stringify({
      ok: true,
      role: acc.role,
      appData: serverData
    })).setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ ok: false, error: String(err) })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  var raw = PropertiesService.getScriptProperties().getProperty("FLL_APP_DATA");
  if (!raw) {
    return ContentService.createTextOutput(JSON.stringify({})).setMimeType(ContentService.MimeType.JSON);
  }
  var serverData = JSON.parse(raw);
  // Đối với truy vấn GET công khai, ẩn toàn bộ điểm số nếu Admin chưa bật allowPrintAndPublish
  var safeData = sanitizeForPublic(serverData);
  return ContentService.createTextOutput(JSON.stringify(safeData)).setMimeType(ContentService.MimeType.JSON);
}`;

  navigator.clipboard.writeText(scriptCode).then(() => {
    showToast("📋 Đã sao chép Mã Google Apps Script (Xác thực uHash/pHash + Phân quyền RG/RUBRIC/ADMIN trên Cloud)!");
  }).catch(() => {
    showToast("⚠️ Không thể tự động copy, vui lòng thử lại!");
  });
}

// Khóa tính năng Xem mã nguồn (View Source / Inspect Element / Chuột phải)
function enableSourceProtection() {
  // Chặn menu chuột phải
  document.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    showToast("🔒 Tính năng chuột phải và xem mã nguồn đã bị khóa để bảo mật kỳ thi!");
    return false;
  });

  // Chặn các phím tắt F12, Ctrl+U, Ctrl+Shift+I/J/C, Ctrl+S
  document.addEventListener("keydown", (e) => {
    const key = (e.key || "").toUpperCase();
    const isF12 = e.key === "F12" || e.keyCode === 123;
    const isCtrlU = (e.ctrlKey || e.metaKey) && key === "U";
    const isCtrlS = (e.ctrlKey || e.metaKey) && key === "S";
    const isDevToolsShortcut = (e.ctrlKey || e.metaKey) && e.shiftKey && ["I", "J", "C", "K"].includes(key);

    if (isF12 || isCtrlU || isCtrlS || isDevToolsShortcut) {
      e.preventDefault();
      e.stopPropagation();
      showToast("🔒 Tính năng xem mã nguồn (View Code / DevTools) đã bị khóa bởi Ban Tổ Chức!");
      return false;
    }
  });
}

// Khởi chạy ứng dụng khi tải trang
window.addEventListener("DOMContentLoaded", () => {
  enableSourceProtection();
  loadData();
  restoreSessionState();
  renderApp();
  if (getCloudCfg().url) {
    pullFromCloud(true);
  }
});
