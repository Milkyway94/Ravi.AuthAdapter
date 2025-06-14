const httpStatus = require('http-status');
const jsonwebtoken = require('jsonwebtoken');

const ConsumerGroups = {
    /** Service group with all permissions */
    SERVICE: 'service',
    /** Staff group with RBAC permissions */
    STAFF: 'staff',
    /** User group with all permissions if granted */
    USER: 'user',
    /** Guest group */
    GUEST: 'guest'
};

/**
 * Configuration for authentication module
 * @type {Object}
 */
const Configs = {
    /** Default permission for user */
    PERMISSION_USER: 'user',

    /** Default permission for staff */
    PERMISSION_LOGGED_IN: 'logged_in',

    /** Default permission for all provider access */
    PERMISSION_ALL_PROVIDER: 'all_provider',

    /** Custom header name */
    HEADER_NAME: 'Authorization',
    /** Include scheme in header */
    HEADER_INCLUDE_SCHEME: true,

    getStaffPermissions: (staffId) => {
        console.log(staffId);
        return [];
    },

    getByAccessToken: (token) => {
        console.log(token);
        return !!token;
    }
};

const HEADER_REGEX = /(\S+)\s+(\S+)/;

/**
 * Get authentication infomation from auth header
 *
 * @param {*} headerValue
 * @returns {Object}
 */
function parseAuthHeader(headerValue) {
    if (typeof headerValue !== 'string') {
        return null;
    }
    if (Configs.HEADER_INCLUDE_SCHEME) {
        const matches = headerValue.match(HEADER_REGEX);
        return (
            matches && { scheme: matches[1].trim(), value: matches[2].trim() }
        );
    }
    return {
        scheme: 'Bearer',
        value: headerValue.trim()
    };
}

/**
 * Get User info from jwt payload
 *
 * @param {Object} jwtPayload
 * @returns {Object}
 */
function getUserFromJwtPayload(jwtPayload) {
    const user = {
        id: jwtPayload.id,
        name: jwtPayload.name,
        phone: jwtPayload.phone,
        username: jwtPayload.username,
        is_admin: jwtPayload.is_admin
    };
    return user;
}

/**
 * Check if staff have all requested permission in jwt payload
 *
 * @param {Request} req
 * @param {Array}  requestedPermissions
 *
 * @returns {Boolean}
 */
function checkStaffPermission(req, requestedPermissions) {
    // check special permission (LoggedIn)
    if (requestedPermissions.includes(Configs.PERMISSION_LOGGED_IN)) {
        return true;
    }
    if (requestedPermissions.length === 0) {
        return false;
    }
    const { permissions } = req.user;
    if (!Array.isArray(permissions) || permissions.length === 0) {
        return false;
    }
    const deniedPermissions = requestedPermissions.filter(
        (permission) => !permissions.includes(permission)
    );
    return deniedPermissions.length !== requestedPermissions.length;
}

/**
 * Check if staff have all requested provider
 *
 * @param {Request} req
 * @param {Array}  requestedProviders
 *
 * @returns {Boolean}
 */
function checkProviderPermission(req, requestedProviders) {
    // check special permission
    const canAccessAllProvider = checkStaffPermission(req, [
        Configs.PERMISSION_ALL_PROVIDER
    ]);
    if (canAccessAllProvider) {
        return true;
    }
    if (requestedProviders.length === 0) {
        return false;
    }

    const {
        tokenInfo: {
            payload: { providers }
        }
    } = req;
    if (!Array.isArray(providers) || providers.length === 0) {
        return false;
    }
    const deniedProviders = requestedProviders.filter(
        (permission) => !providers.includes(permission)
    );
    return deniedProviders.length === 0;
}

/**
 * Get JWT payload from authorization header
 *
 * @param {Request} req
 */
const getTokenInfo = async (req) => {
    let jwt = req.get(Configs.HEADER_NAME);
    if (!jwt) {
        return null;
    }
    jwt = parseAuthHeader(
        jwt
    );
    if (jwt === null) {
        return null;
    }
    jwt.payload = jsonwebtoken.decode(
        jwt.value,
        { json: true }
    );
    if (await Configs.getByAccessToken(jwt.value)) {
        return jwt;
    }
    return null;
};

/**
 * Get authentication info from proxy header
 *
 * @param {Request} req
 */
const getAuthInfo = (req) => {
    // console.log(req.headers);
    let consumerGroups = req.get('x-request-group') || '';

    if (req.user) {
        consumerGroups = req.user.is_admin
            ? ConsumerGroups.SERVICE
            : ConsumerGroups.STAFF;
    }

    consumerGroups = consumerGroups
        .split(',')
        .filter((item) => item.length > 0);

    let accessLevel = ConsumerGroups.GUEST;
    const allAccessLevels = Object.values(ConsumerGroups);
    for (let index = 0; index < allAccessLevels.length; index += 1) {
        if (consumerGroups.includes(allAccessLevels[index])) {
            accessLevel = allAccessLevels[index];
            break;
        }
    }

    return {
        clientId: req.get('x-client-id') || null,
        accessLevel
    };
};

/**
 * Load auth info to request
 *
 * @param {Request} req
 */
const loadInfo = async (req) => {
    let tokenInfo = await getTokenInfo(
        req
    );
    let user = null;
    if (tokenInfo === null || !tokenInfo.payload) {
        tokenInfo = null;
    } else {
        user = getUserFromJwtPayload(tokenInfo.payload);
    }
    req.user = user;
    req.tokenInfo = tokenInfo;
    req.authInfo = getAuthInfo(req);

    // load permission for staff
    if (req.authInfo.accessLevel === ConsumerGroups.STAFF && user !== null) {
        req.user.permissions = await Configs.getStaffPermissions(user.id);
    }
};

/**
 * Check user has required permission
 *
 * @param {Request} req
 * @param {Array} permissions
 * @param {Function} additionalCheck
 */
const checkPermission = async (req, permissions, additionalCheck) => {
    const apiError = {
        message: 'Unauthorized',
        status: httpStatus.UNAUTHORIZED,
        stack: undefined
    };
    const permissionsToCheck = Array.isArray(permissions)
        ? permissions.slice(0)
        : [];

    // allow if require no permission
    if (permissionsToCheck.length === 0) {
        return null;
    }

    // get user permission userPermissionIndex in permission array
    const userPermissionIndex = permissionsToCheck.indexOf(
        Configs.PERMISSION_USER
    );

    switch (req.authInfo.accessLevel) {
        case ConsumerGroups.SERVICE:
            // allow all access with service level
            return null;
        case ConsumerGroups.STAFF:
            // remove user permission
            if (userPermissionIndex !== -1) {
                permissionsToCheck.splice(userPermissionIndex, 1);
            }
            if (!checkStaffPermission(req, permissionsToCheck)) {
                apiError.status = httpStatus.FORBIDDEN;
                apiError.message = 'Forbidden';
                return apiError;
            }
            break;
        case ConsumerGroups.USER:
            if (permissionsToCheck.indexOf(Configs.PERMISSION_USER) === -1) {
                apiError.status = httpStatus.FORBIDDEN;
                apiError.message = 'Forbidden';
                return apiError;
            }
            break;
        default:
            // reject guest access
            return apiError;
    }

    // check permission by additionalCheck (only user and staff)
    if (additionalCheck && !(await additionalCheck(req))) {
        apiError.status = httpStatus.FORBIDDEN;
        apiError.message = 'Forbidden';
        return apiError;
    }
    return null;
};

/**
 * Handle JWT token
 *
 * @param {Request}     req
 * @param {Response}    res
 * @param {Function}    next
 * @param {Array}       permissions user-config permission
 * @param {Function}    additionalCheck additional checking function
 */
const handleJWT = async (
    req,
    res,
    next,
    permissions,
    additionalCheck = null,
    includeCheckPermission = true
) => {
    // Load auth info to request
    await loadInfo(
        req
    );

    if (!includeCheckPermission) {
        return true;
    }

    // check user permission
    const permissionCheckResult = await checkPermission(
        req,
        permissions,
        additionalCheck
    );
    if (permissionCheckResult) {
        // Throw permission error
        return false;
    }
    return true;
};

/**
 * Authenticate middleware with express
 *
 * @param {Array}    permissions
 * @param {Function} additionalCheck
 * @param {Boolean} includeCheckPermission
 */
const authorize = (permissions, additionalCheck, includeCheckPermission) => (
    req,
    res,
    next
) => handleJWT(
    req,
    res,
    next,
    permissions,
    additionalCheck,
    includeCheckPermission
);

module.exports = {
    ConsumerGroups,
    Configs,
    getAuthInfo,
    getTokenInfo,
    authorize,
    checkStaffPermission,
    checkProviderPermission
};
