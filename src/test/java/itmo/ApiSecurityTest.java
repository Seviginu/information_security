package itmo;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import com.jayway.jsonpath.JsonPath;
import itmo.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "app.demo.password=Test-only-password-123!",
        "app.demo.other-password=Test-only-other-password-123!"
})
@AutoConfigureMockMvc
class ApiSecurityTest {
    private static final String PASSWORD = "Test-only-password-123!";
    private static final String OTHER_PASSWORD = "Test-only-other-password-123!";
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;

    @Test
    void loginIssuesTokenAndAllowsReading() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login("student", PASSWORD)))
                .andExpect(status().isOk()).andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$[0].id").exists())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }

    @Test
    void bothDataEndpointsRequireToken() throws Exception {
        mvc.perform(get("/api/data")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/data").contentType(MediaType.APPLICATION_JSON)
                .content("{\"content\":\"test\"}")).andExpect(status().isUnauthorized());
        mvc.perform(put("/api/data/" + UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"content\":\"test\"}")).andExpect(status().isUnauthorized());
    }

    @Test
    void wrongPasswordAndUnknownLoginHaveSameError() throws Exception {
        String first = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("login", "student", "password", "wrong"))))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        String second = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("login", "missing", "password", "wrong"))))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        assertThat(first).isEqualTo(second);
    }

    @Test
    void sqlInjectionDoesNotBypassLogin() throws Exception {
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("login", "student' OR '1'='1", "password", PASSWORD))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidAndTamperedTokensAreRejected() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer invalid"))
                .andExpect(status().isUnauthorized());
        String[] parts = login("student", PASSWORD).split("\\.");
        String signature = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + parts[0] + "." + parts[1] + "." + signature))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + token(SecurityConfig.ISSUER, -120)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + token("another-app", 900)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void xssIsEscapedOnCreationAndRead() throws Exception {
        String auth = "Bearer " + login("student", PASSWORD);
        String escaped = "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;";
        mvc.perform(post("/api/data").header("Authorization", auth).contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("content", "<script>alert('xss')</script>"))))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.content").value(escaped));
        mvc.perform(get("/api/data").header("Authorization", auth))
                .andExpect(status().isOk()).andExpect(jsonPath("$[*].content", hasItem(escaped)));
    }

    @Test
    void sqlPayloadIsStoredAsText() throws Exception {
        String payload = "'); DROP TABLE note; --";
        mvc.perform(post("/api/data").header("Authorization", "Bearer " + login("student", PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("content", payload))))
                .andExpect(status().isCreated());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM note WHERE content = ?", Integer.class, payload)).isEqualTo(1);
    }

    @Test
    void usersCannotReadEachOthersNotes() throws Exception {
        jdbc.update("DELETE FROM note WHERE owner = ?", "other");
        String auth = "Bearer " + login("other", OTHER_PASSWORD);
        mvc.perform(get("/api/data").header("Authorization", auth))
                .andExpect(status().isOk()).andExpect(content().json("[]"));
        mvc.perform(post("/api/data").header("Authorization", auth).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"private-other-note\"}"))
                .andExpect(status().isCreated());
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login("student", PASSWORD)))
                .andExpect(jsonPath("$[*].content", not(hasItem("private-other-note"))));
    }

    @Test
    void otherUserCannotUpdateNoteAndGetsSameResponseAsForMissingNote() throws Exception {
        String ownerToken = login("student", PASSWORD);
        String otherToken = login("other", OTHER_PASSWORD);
        String created = mvc.perform(post("/api/data").header("Authorization", "Bearer " + ownerToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"original\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String id = JsonPath.read(created, "$.id");
        String forbidden = mvc.perform(put("/api/data/" + id)
                        .header("Authorization", "Bearer " + otherToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"changed\"}"))
                .andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
        String missing = mvc.perform(put("/api/data/" + UUID.randomUUID())
                        .header("Authorization", "Bearer " + otherToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"changed\"}"))
                .andExpect(status().isNotFound()).andReturn().getResponse().getContentAsString();
        assertThat(forbidden).isEqualTo(missing);
        assertThat(jdbc.queryForObject("SELECT content FROM note WHERE id = ?", String.class, UUID.fromString(id)))
                .isEqualTo("original");
    }

    @Test
    void ownerCanUpdateNoteWithValidationAndEscaping() throws Exception {
        String token = login("student", PASSWORD);
        String created = mvc.perform(post("/api/data").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"original\"}"))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String id = JsonPath.read(created, "$.id");
        mvc.perform(put("/api/data/" + id).header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"   \"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(put("/api/data/" + id).header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"<script>1</script>\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").value("&lt;script&gt;1&lt;/script&gt;"));
        assertThat(jdbc.queryForObject("SELECT content FROM note WHERE id = ?", String.class, UUID.fromString(id)))
                .isEqualTo("<script>1</script>");
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + token))
                .andExpect(jsonPath("$[*].content", hasItem("&lt;script&gt;1&lt;/script&gt;")));
    }

    @Test
    void passwordStoredAsBcryptHash() {
        for (var credentials : Map.of("student", PASSWORD, "other", OTHER_PASSWORD).entrySet()) {
            String hash = jdbc.queryForObject("SELECT password_hash FROM app_user WHERE username = ?",
                    String.class, credentials.getKey());
            assertThat(hash).startsWith("$2a$12$").isNotEqualTo(credentials.getValue());
            assertThat(passwords.matches(credentials.getValue(), hash)).isTrue();
        }
    }

    @Test
    void invalidInputIsRejectedWithoutReflectingIt() throws Exception {
        String auth = "Bearer " + login("student", PASSWORD);
        for (String value : new String[]{" ", "a".repeat(2001)}) {
            mvc.perform(post("/api/data").header("Authorization", auth).contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(Map.of("content", value))))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("Некорректный запрос"));
        }
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("{broken"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("login", "student", "password", "я".repeat(40)))))
                .andExpect(status().isBadRequest());
    }

    private String login(String login, String password) throws Exception {
        String body = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("login", login, "password", password))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.accessToken");
    }

    private String token(String issuer, long expiresIn) {
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(issuer).subject("student")
                .issuedAt(now.minusSeconds(3600)).expiresAt(now.plusSeconds(expiresIn)).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
                .getTokenValue();
    }
}
