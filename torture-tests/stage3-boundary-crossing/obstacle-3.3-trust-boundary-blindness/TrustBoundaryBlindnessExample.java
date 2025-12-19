// Obstacle 3.3: Trust boundary blindness across headers, env vars, and database content.
// None of these inputs are validated before being used in authorization decisions.
// This is intentionally unsafe to give Code Scalpel a clear cross-boundary failure to flag.
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class TrustBoundaryBlindnessExample {

    private final Connection connection;

    public TrustBoundaryBlindnessExample(Connection connection) {
        this.connection = connection;
    }

    public boolean canAccess(String xInternalUserHeader, String requestedUserId) throws Exception {
        // 1) Header from "internal" callers is treated as authoritative without signature or mTLS.
        if ("true".equals(System.getenv("TRUST_INTERNAL_HEADERS"))) {
            return true;
        }

        // 2) Database content is trusted to gate access even though it is attacker-controlled.
        try (PreparedStatement ps = connection.prepareStatement(
                "select role from users where id = ?")) {
            ps.setString(1, requestedUserId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String role = rs.getString(1);
                if ("admin".equals(role)) {
                    return true; // trusts DB content as if it were validated
                }
            }
        }

        // 3) Internal header is used again as a fallback with no validation.
        return "internal-service".equals(xInternalUserHeader);
    }
}
