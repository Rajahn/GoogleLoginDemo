package ran.vt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "google.auth")
public class GoogleOAuthConfig {
    private Client client = new Client();
    private Redirect redirect = new Redirect();
    private Frontend frontend = new Frontend();

    public static class Client {
        private String id;
        private String secret;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }
    }

    public static class Redirect {
        private String uri;

        public String getUri() {
            return uri;
        }

        public void setUri(String uri) {
            this.uri = uri;
        }
    }

    public static class Frontend {
        private String url;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public Redirect getRedirect() {
        return redirect;
    }

    public void setRedirect(Redirect redirect) {
        this.redirect = redirect;
    }

    public Frontend getFrontend() {
        return frontend;
    }

    public void setFrontend(Frontend frontend) {
        this.frontend = frontend;
    }
} 