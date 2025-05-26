package org.example.statelessspringsecuritydemo.config;

import org.springframework.security.web.authentication.WebAuthenticationDetails;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Objects;

public class StatelessWebAuthenticationDetails extends WebAuthenticationDetails {

    private final String remoteAddress;

    public StatelessWebAuthenticationDetails(HttpServletRequest request) {
        // Rufe NICHT super(request) auf, um getSession() zu vermeiden
        super(request.getRemoteAddr(), null); // Verwende den alternativen Konstruktor
        this.remoteAddress = request.getRemoteAddr();
    }

    @Override
    public String getRemoteAddress() {
        return this.remoteAddress;
    }

    @Override
    public String getSessionId() {
        return null; // Keine Session-ID
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof StatelessWebAuthenticationDetails) {
            StatelessWebAuthenticationDetails other = (StatelessWebAuthenticationDetails) obj;
            return Objects.equals(this.remoteAddress, other.remoteAddress);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(remoteAddress);
    }

    @Override
    public String toString() {
        return "StatelessWebAuthenticationDetails [RemoteIpAddress=" + remoteAddress + ", SessionId=null]";
    }
}