package ran.vt.model;

import java.io.Serializable;

public class User implements Serializable {
    private Long id;
    private String email;
    private String name;
    private String googleId;

    public User() {
    }

    public User(Long id, String email, String name, String googleId) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.googleId = googleId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGoogleId() {
        return googleId;
    }

    public void setGoogleId(String googleId) {
        this.googleId = googleId;
    }
} 