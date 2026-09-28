package itmo.data;

import java.util.List;
import java.util.UUID;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
@RequestMapping("/api/data")
public class DataController {
    private final JdbcTemplate jdbc;

    public DataController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping
    public List<NoteResponse> list(@AuthenticationPrincipal Jwt jwt) {
        return jdbc.query("SELECT id, content FROM note WHERE owner = ? ORDER BY id",
                (rs, row) -> response(rs.getObject("id", UUID.class), rs.getString("content")),
                jwt.getSubject());
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public NoteResponse create(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody NoteRequest request) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO note (id, owner, content) VALUES (?, ?, ?)",
                id, jwt.getSubject(), request.content());
        return response(id, request.content());
    }

    @PutMapping("/{id}")
    public NoteResponse update(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID id,
                               @Valid @RequestBody NoteRequest request) {
        int updated = jdbc.update("UPDATE note SET content = ? WHERE id = ? AND owner = ?",
                request.content(), id, jwt.getSubject());
        if (updated == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return response(id, request.content());
    }

    private static NoteResponse response(UUID id, String content) {
        return new NoteResponse(id, HtmlUtils.htmlEscape(content, "UTF-8"));
    }

    public record NoteRequest(@NotBlank @Size(max = 2000) String content) {}
    public record NoteResponse(UUID id, String content) {}
}
