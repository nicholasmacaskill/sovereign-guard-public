import { Request, Response, NextFunction } from 'express';
// Note: This is a boilerplate snippet assuming an Express.js environment.

// Load Policy (In a real app, import this properly)
import policy from './security_policy.json';

interface AuthRequest extends Request {
    user?: {
        roles: string[];
        authMethod: string;
        verified: boolean;
    };
}

export const sovereignAuthMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
    const isAdminRoute = req.path.startsWith('/admin');

    if (!isAdminRoute) {
        return next();
    }

    // 1. Check if user is authenticated
    if (!req.user || !req.user.verified) {
        return res.status(401).json({ error: 'Unauthorized: Authentication required.' });
    }

    // 2. Enforce Authentication Method
    const method = req.user.authMethod;
    if (!policy.authentication.allowedMethods.includes(method)) {
        console.error(`[SECURITY ALERT] Blocked access attempt using forbidden method: ${method}`);
        return res.status(403).json({
            error: 'Forbidden: Sovereign Policy Violation.',
            message: `Authentication method '${method}' is not permitted for admin routes. Hardware keys (FIDO2/WebAuthn) only.`
        });
    }

    // 3. Check for explicitly forbidden methods (Redundant but explicit safety)
    if (policy.authentication.forbiddenMethods.includes(method)) {
        return res.status(403).json({ error: 'Forbidden: Insecure authentication method detected.' });
    }

    next();
};

export const requireHardwareKey = async (req: AuthRequest, res: Response, next: NextFunction) => {
    // Helper to specifically check for hardware key presence in session metadata
    // ... logic to verify FIDO2 attestation would go here ...
    next();
};
