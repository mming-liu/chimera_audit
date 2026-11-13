"""6 realistic one-click presets for demo: 4 real 0-days + 2 false-positive traps."""

from dataclasses import dataclass


@dataclass
class Preset:
    """Single demo preset."""
    id: str
    label: str
    category: str
    code: str
    language: str
    filename: str
    expected_verdict: bool
    description: str


# ============================================================================
# PRESET 1: Multi-Hop FileWriter Escape (0-Day #1)
# ============================================================================
PRESET_FILEWRITER_ESCAPE = Preset(
    id="0day_1_filewriter",
    label="[0-Day #1] Multi-Hop FileWriter Escape",
    category="pathtraver",
    code="""
public class FileUploadController {
    private FileUploadService uploadService;
    
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("path") String userPath, @RequestParam("file") MultipartFile file) {
        String result = uploadService.processUpload(userPath, file);
        return ResponseEntity.ok(result);
    }
}

public class FileUploadService {
    public String processUpload(String userPath, MultipartFile file) {
        String tempPath = prepareDirectoryPath(userPath);
        writeToFile(tempPath, file);
        return "uploaded";
    }
    
    private String prepareDirectoryPath(String input) {
        // No normalization!
        return "/uploads/" + input;
    }
    
    private void writeToFile(String filePath, MultipartFile file) throws IOException {
        FileWriter writer = new FileWriter(filePath);
        writer.write(new String(file.getBytes()));
        writer.close();
    }
}
""",
    language="java",
    filename="FileUploadController.java",
    expected_verdict=True,
    description="Multi-hop path traversal: @RequestParam → uploadService → FileWriter with no normalization"
)


# ============================================================================
# PRESET 2: Workflow JSON SQLi (0-Day #2)
# ============================================================================
PRESET_WORKFLOW_SQLI = Preset(
    id="0day_2_workflow_sqli",
    label="[0-Day #2] Workflow JSON SQLi",
    category="sqli",
    code="""
@RestController
@RequestMapping("/api/workflow")
public class WorkflowController {
    @Autowired
    private WorkflowService workflowService;
    
    @PostMapping("/search")
    public ResponseEntity<?> searchMapStr(@RequestBody Map<String, String> searchParams) {
        String query = workflowService.buildQuery(searchParams);
        return ResponseEntity.ok(query);
    }
}

@Service
public class WorkflowService {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    public String buildQuery(Map<String, String> params) {
        String searchTerm = params.get("keyword");
        String rawQuery = "SELECT * FROM workflows WHERE name LIKE '%" + searchTerm + "%'";
        return jdbcTemplate.queryForMap(rawQuery).toString();
    }
}
""",
    language="java",
    filename="WorkflowController.java",
    expected_verdict=True,
    description="SQL injection via string concatenation in LIKE clause"
)


# ============================================================================
# PRESET 3: Bare @PostMapping Authz Bypass (0-Day #3)
# ============================================================================
PRESET_AUTHZ_BYPASS = Preset(
    id="0day_3_authz_bypass",
    label="[0-Day #3] Bare @PostMapping Authz Bypass",
    category="authz",
    code="""
@RestController
@RequestMapping("/api/s3")
public class AliPayController {
    
    @PostMapping("/downloadS3Storage")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> downloadS3Storage(@RequestParam String objectKey) {
        // This is guarded
        return ResponseEntity.ok(s3Client.getObject(objectKey));
    }
    
    @PostMapping("/uploadS3Storage")
    public ResponseEntity<?> uploadS3Storage(@RequestParam String objectKey, @RequestBody byte[] data) {
        // This is NOT guarded - siblings have auth, but this write endpoint is missing it!
        s3Client.putObject(objectKey, data);
        return ResponseEntity.ok("uploaded");
    }
}
""",
    language="java",
    filename="AliPayController.java",
    expected_verdict=True,
    description="Write endpoint uploadS3Storage missing @PreAuthorize while sibling downloadS3Storage has it"
)


# ============================================================================
# PRESET 4: Chunk Upload Traversal (0-Day #4)
# ============================================================================
PRESET_CHUNK_TRAVERSAL = Preset(
    id="0day_4_chunk_traversal",
    label="[0-Day #4] Chunk Upload Traversal",
    category="pathtraver",
    code="""
@RestController
@RequestMapping("/api/upload")
public class ChunkUploadController {
    
    @PostMapping("/chunk")
    public ResponseEntity<?> uploadChunk(@RequestParam("chunkName") String chunkName, @RequestBody byte[] data) {
        String uploadDir = "/tmp/chunks";
        String finalPath = uploadDir + File.separator + chunkName;
        Files.write(Paths.get(finalPath), data);
        return ResponseEntity.ok("chunk saved");
    }
}
""",
    language="java",
    filename="ChunkUploadController.java",
    expected_verdict=True,
    description="Path traversal via chunkName parameter: user can use ../ to escape /tmp/chunks"
)


# ============================================================================
# PRESET 5: Tomcat @PathVariable Guard - FALSE POSITIVE TRAP (FP #1)
# ============================================================================
PRESET_TOMCAT_PATHVAR_GUARD = Preset(
    id="fp_trap_1_pathvar_guard",
    label="[FP Trap #1] Tomcat @PathVariable Guard",
    category="pathtraver",
    code="""
@RestController
@RequestMapping("/api/files")
public class FileController {
    
    @GetMapping("/download/{fileName}")
    public ResponseEntity<?> downloadFile(@PathVariable String fileName) {
        // Single-segment @PathVariable without URLDecoder or {*wildcard}
        // Tomcat 10.1 + Spring MVC 6.1 normalizes single-segment @PathVariable
        // Blocks %2F (/) and %2E%2E (..) automatically
        String filePath = "/safe/files/" + fileName;
        return ResponseEntity.ok(Files.readAllBytes(Paths.get(filePath)));
    }
}
""",
    language="java",
    filename="FileController.java",
    expected_verdict=False,
    description="SAFE: Single-segment @PathVariable is normalized by Tomcat container guard - NOT vulnerable"
)


# ============================================================================
# PRESET 6: NamedParameter SQL Builder - FALSE POSITIVE TRAP (FP #2)
# ============================================================================
PRESET_NAMEDPARAM_BUILDER = Preset(
    id="fp_trap_2_namedparam",
    label="[FP Trap #2] NamedParam SQL Builder",
    category="sqli",
    code="""
@RestController
@RequestMapping("/api/search")
public class SearchController {
    @Autowired
    private NamedParameterJdbcTemplate namedTemplate;
    
    @GetMapping("/users")
    public ResponseEntity<?> searchUsers(@RequestParam String sourceParam) {
        String query = "SELECT * FROM users WHERE source = :source";
        SqlParameterSource namedParams = new MapSqlParameterSource("source", sourceParam);
        List<User> results = namedTemplate.query(query, namedParams, (rs, rowNum) -> {
            return new User(rs.getLong("id"), rs.getString("name"));
        });
        return ResponseEntity.ok(results);
    }
}
""",
    language="java",
    filename="SearchController.java",
    expected_verdict=False,
    description="SAFE: Named parameter :source with addValue() - NOT vulnerable to SQL injection"
)


# ============================================================================
# Preset Registry
# ============================================================================

PRESETS = [
    PRESET_FILEWRITER_ESCAPE,
    PRESET_WORKFLOW_SQLI,
    PRESET_AUTHZ_BYPASS,
    PRESET_CHUNK_TRAVERSAL,
    PRESET_TOMCAT_PATHVAR_GUARD,
    PRESET_NAMEDPARAM_BUILDER,
]


def get_preset_by_id(preset_id: str) -> Preset:
    """Get a preset by ID."""
    for preset in PRESETS:
        if preset.id == preset_id:
            return preset
    return None


def get_all_presets() -> list[Preset]:
    """Get all presets."""
    return PRESETS


def preset_to_dict(preset: Preset) -> dict:
    """Convert preset to API response dict."""
    return {
        "id": preset.id,
        "label": preset.label,
        "category": preset.category,
        "code": preset.code,
        "language": preset.language,
        "filename": preset.filename,
        "expected_verdict": preset.expected_verdict,
        "description": preset.description,
    }
