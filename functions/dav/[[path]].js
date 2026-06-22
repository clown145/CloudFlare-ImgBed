// WebDAV 服务支持
import { fetchOthersConfig } from "../utils/sysConfig";
import { getDatabase } from "../utils/databaseAdapter";
import { createApiToken } from "../api/manage/apiTokens";
import { addFileToIndex } from "../utils/indexManager";
import { sanitizeFileName, sanitizeUploadFolder } from "../upload/uploadTools";

const WEBDAV_INTERNAL_TOKEN_NAME = 'WebDAV Internal Token';
const WEBDAV_INTERNAL_PERMISSIONS = ['list', 'upload', 'delete', 'manage'];

export async function onRequest(context) {
    const { request, env } = context;

    const url = new URL(request.url);
    if (url.pathname === '/dav') {
        url.pathname = '/dav/';
        return Response.redirect(url.toString(), 301);
    }

    const authResponse = await checkAuth(request, env);
    if (authResponse) return authResponse;

    url.pathname = url.pathname.replace(/^\/dav/, '') || '/';
    const modifiedRequest = new Request(url.toString(), request);

    switch (modifiedRequest.method) {
        case 'OPTIONS': return handleOptions(modifiedRequest);
        case 'HEAD': return handleHead(modifiedRequest, env);
        case 'PROPFIND': return handlePropfind(modifiedRequest, env);
        case 'PUT': return handlePut(modifiedRequest, env);
        case 'DELETE': return handleDelete(modifiedRequest, env);
        case 'GET': return handleGet(modifiedRequest, env);
        case 'MOVE': return handleMove(modifiedRequest, env, context);
        case 'MKCOL': return handleMkcol(modifiedRequest, env);
        default: return new Response('Method Not Allowed', { status: 405 });
    }
}

// --- UTILITY FUNCTIONS ---

function isWebDAVInternalToken(tokenData) {
    return tokenData?.type === 'internal'
        || (tokenData?.owner === 'system' && tokenData?.name === WEBDAV_INTERNAL_TOKEN_NAME);
}

function setNoStoreHeaders(headers) {
    headers.set('Cache-Control', 'no-store');
    headers.set('Pragma', 'no-cache');
    headers.set('Expires', '0');
}

function createNoStoreFetchInit(init = {}) {
    const headers = new Headers(init.headers);
    setNoStoreHeaders(headers);
    headers.set('X-WebDAV-Internal', '1');

    return {
        ...init,
        headers,
        cf: {
            ...init.cf,
            cacheTtl: 0,
            cacheEverything: false,
        },
    };
}

async function saveWebDAVInternalToken(db, token, tokenId) {
    const settingsStr = await db.get('manage@sysConfig@others');
    const settings = settingsStr ? JSON.parse(settingsStr) : {};
    if (!settings.webDAV) settings.webDAV = {};
    settings.webDAV.internalToken = token;
    settings.webDAV.internalTokenId = tokenId;
    await db.put('manage@sysConfig@others', JSON.stringify(settings));
}

async function collectionExists(env, request, path) {
    const cleanPath = path.replace(/^\/+|\/+$/g, '');
    if (!cleanPath) return false;

    const db = getDatabase(env);
    const prefix = `${cleanPath}/`;
    const existing = await db.getWithMetadata(prefix);
    if (existing && existing.value !== null) {
        return true;
    }

    const listUrl = new URL('/api/manage/list', request.url);
    listUrl.searchParams.set('dir', cleanPath);
    listUrl.searchParams.set('count', '1');
    const listResponse = await fetch(listUrl.toString(), { headers: await getApiHeaders(env) });
    if (!listResponse.ok) {
        throw new Error(`Failed to check collection: ${listResponse.status}`);
    }

    const result = await listResponse.json();
    return (result.files && result.files.length > 0)
        || (result.directories && result.directories.length > 0);
}

async function fileExists(db, path) {
    const fileData = await db.getWithMetadata(path);
    return !!(fileData && fileData.value !== null && fileData.metadata?.FileType !== 'directory');
}

async function resourceExists(env, request, path) {
    const cleanPath = path.replace(/^\/+|\/+$/g, '');
    if (!cleanPath) {
        return {
            exists: true,
            isFolder: true,
            isFile: false,
        };
    }

    const db = getDatabase(env);
    const fileData = await db.getWithMetadata(cleanPath);
    const isFile = !!(fileData && fileData.value !== null && fileData.metadata?.FileType !== 'directory');
    const isFolder = await collectionExists(env, request, cleanPath);

    return {
        exists: isFile || isFolder,
        isFile,
        isFolder,
        fileData,
    };
}

async function deleteResource(env, request, path, isFolder) {
    const cleanPath = path.replace(/^\/+|\/+$/g, '');
    if (!cleanPath) {
        return { success: false, message: 'Cannot delete root collection' };
    }

    const deleteUrl = new URL(`/api/manage/delete/${encodeURIComponent(cleanPath)}`, request.url);
    if (isFolder) {
        deleteUrl.searchParams.set('folder', 'true');
    }

    const response = await fetch(deleteUrl.toString(), {
        method: 'DELETE',
        headers: await getApiHeaders(env)
    });

    let result = null;
    const responseText = await response.text();
    try {
        result = responseText ? JSON.parse(responseText) : null;
    } catch (error) {
        result = null;
    }

    if (!response.ok || result?.success === false) {
        return {
            success: false,
            status: response.status,
            message: result?.error || result?.message || responseText || response.statusText || 'Delete failed',
        };
    }

    return { success: true, result };
}

function isUnsupportedMoveMetadata(metadata) {
    return (metadata?.Channel === 'Telegram' || metadata?.Channel === undefined)
        && metadata?.FileType !== 'directory';
}

async function getApiHeaders(env) {
    const othersConfig = await fetchOthersConfig(env);
    let token = othersConfig.webDAV.internalToken;
    let tokenId = othersConfig.webDAV.internalTokenId;

    const db = getDatabase(env);

    const securityStr = await db.get('manage@sysConfig@security');
    const securitySettings = securityStr ? JSON.parse(securityStr) : {};
    if (!securitySettings.apiTokens) securitySettings.apiTokens = {};
    if (!securitySettings.apiTokens.tokens) securitySettings.apiTokens.tokens = {};
    const tokens = securitySettings.apiTokens.tokens;

    let tokenData = tokenId && tokens[tokenId] ? tokens[tokenId] : null;
    let securityChanged = false;

    if (!tokenData && token) {
        for (const [id, data] of Object.entries(tokens)) {
            if (data.token === token && isWebDAVInternalToken(data)) {
                tokenId = id;
                tokenData = data;
                await saveWebDAVInternalToken(db, token, tokenId);
                break;
            }
        }
    }

    if (!token || !tokenData || !isWebDAVInternalToken(tokenData)) {
        const tokenResult = await createApiToken(
            db,
            WEBDAV_INTERNAL_TOKEN_NAME,
            WEBDAV_INTERNAL_PERMISSIONS,
            'system',
            null,
            false,
            'internal'
        );
        token = tokenResult.token;
        tokenId = tokenResult.id;
        await saveWebDAVInternalToken(db, token, tokenId);
    } else {
        token = tokenData.token;

        const permissions = Array.isArray(tokenData.permissions) ? tokenData.permissions : [];
        for (const permission of WEBDAV_INTERNAL_PERMISSIONS) {
            if (!permissions.includes(permission)) {
                permissions.push(permission);
                securityChanged = true;
            }
        }

        if (tokenData.type !== 'internal') {
            tokenData.type = 'internal';
            securityChanged = true;
        }

        if (securityChanged) {
            tokenData.permissions = permissions;
            tokenData.updatedAt = new Date().toISOString();
            await db.put('manage@sysConfig@security', JSON.stringify(securitySettings));
        }

        if (tokenId !== othersConfig.webDAV.internalTokenId || token !== othersConfig.webDAV.internalToken) {
            await saveWebDAVInternalToken(db, token, tokenId);
        }
    }

    return {
        'Authorization': `Bearer ${token}`,
    };
}

async function checkAuth(request, env) {
    const othersConfig = await fetchOthersConfig(env);

    const enabled = othersConfig.webDAV.enabled;
    if (!enabled) return new Response('WebDAV is disabled', { status: 403 }); // WebDAV disabled

    const davUser = othersConfig.webDAV.username;
    const davPass = othersConfig.webDAV.password;
    if (!davUser || !davPass) return null; // No auth required

    const authHeader = request.headers.get('Authorization');
    if (!authHeader) {
        return new Response('Authorization required', {
            status: 401,
            headers: { 'WWW-Authenticate': 'Basic realm="WebDAV"' },
        });
    }

    const [scheme, encoded] = authHeader.split(' ');
    if (scheme !== 'Basic' || !encoded) {
        return new Response('Malformed Authorization header', { status: 400 });
    }

    const [user, pass] = atob(encoded).split(':');
    if (user !== davUser || pass !== davPass) {
        return new Response('Invalid credentials', { status: 403 });
    }

    return null;
}

// --- WEBDAV METHOD HANDLERS ---

function handleOptions(request) {
    return new Response(null, {
        status: 200,
        headers: {
            'Allow': 'OPTIONS, HEAD, GET, PUT, DELETE, PROPFIND, MOVE, MKCOL',
            'DAV': '1',
            'MS-Author-Via': 'DAV',
        },
    });
}

async function handleHead(request, env) {
    const path = decodeURIComponent(new URL(request.url).pathname);

    if (path.endsWith('/')) {
        if (path !== '/') {
            const dir = path.startsWith('/') ? path.substring(1) : path;
            const resource = await resourceExists(env, request, dir);
            if (!resource.isFolder) {
                return new Response(null, { status: 404 });
            }
        }

        return new Response(null, {
            status: 200,
            headers: {
                'Content-Type': 'text/html; charset=utf-8',
                'DAV': '1',
                'Cache-Control': 'no-store',
            },
        });
    }

    try {
        const fileUrl = new URL(request.url);
        fileUrl.pathname = `/file${fileUrl.pathname}`;
        const fileResponse = await fetch(fileUrl.toString(), createNoStoreFetchInit({ method: 'HEAD' }));

        const response = new Response(null, {
            status: fileResponse.status,
            statusText: fileResponse.statusText,
            headers: fileResponse.headers,
        });
        setNoStoreHeaders(response.headers);
        return response;
    } catch (error) {
        console.error('HEAD failed:', error.stack);
        return new Response(null, { status: 500 });
    }
}

async function handleGet(request, env) {
    const path = decodeURIComponent(new URL(request.url).pathname);

    if (path.endsWith('/')) { // Directory listing
        try {
            const dir = path === '/' ? '' : path.substring(1, path.length - 1);
            const contents = await fetchDirectoryContents(dir, env, request);
            const html = generateDirectoryListingHtml(path, contents);
            return new Response(html, {
                headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Cache-Control': 'no-store',
                },
            });
        } catch (error) {
            console.error('GET (directory) failed:', error.stack);
            return new Response(`Error listing directory: ${error.message}`, { status: 500 });
        }
    } else { // File download
        try {
            const fileUrl = new URL(request.url);
            fileUrl.pathname = `/file${fileUrl.pathname}`;

            const fileResponse = await fetch(fileUrl.toString(), createNoStoreFetchInit());

            if (!fileResponse.ok) {
                 return new Response('File not found', { status: fileResponse.status, statusText: fileResponse.statusText });
            }

            const response = new Response(fileResponse.body, fileResponse);
            response.headers.set('Access-Control-Allow-Origin', '*');
            setNoStoreHeaders(response.headers);

            return response;
        } catch (error) {
            console.error('GET (file) failed:', error.stack);
            return new Response(`Error getting file: ${error.message}`, { status: 500 });
        }
    }
}

async function handlePut(request, env) {
    const fullPath = decodeURIComponent(new URL(request.url).pathname.substring(1));
    if (!fullPath || fullPath.endsWith('/')) {
        return new Response('Invalid file name', { status: 400 });
    }

    const lastSlashIndex = fullPath.lastIndexOf('/');
    const rawUploadFolder = lastSlashIndex > -1 ? fullPath.substring(0, lastSlashIndex) : '';
    const fileName = lastSlashIndex > -1 ? fullPath.substring(lastSlashIndex + 1) : fullPath;
    let uploadFolder = '';
    let targetPath = '';

    try {
        uploadFolder = sanitizeUploadFolder(rawUploadFolder);
        const sanitizedFileName = sanitizeFileName(fileName);
        if (!sanitizedFileName) {
            return new Response('Invalid file name', { status: 400 });
        }
        targetPath = uploadFolder ? `${uploadFolder}/${sanitizedFileName}` : sanitizedFileName;
    } catch (error) {
        return new Response('Invalid file name', { status: 400 });
    }

    try {
        if (await collectionExists(env, request, targetPath)) {
            return new Response('Conflict: collection exists with the same name', { status: 409 });
        }

        const db = getDatabase(env);
        if (await fileExists(db, targetPath)) {
            const deleteResult = await deleteResource(env, request, targetPath, false);
            if (!deleteResult.success) {
                return new Response(`Failed to delete existing destination file: ${deleteResult.message}`, { status: 500 });
            }
        }
    } catch (error) {
        console.error('PUT destination preparation failed:', error.stack);
        return new Response(`Internal server error: ${error.message}`, { status: 500 });
    }

    const fileContent = await request.blob();
    const formData = new FormData();
    formData.append('file', fileContent, fileName);

    const uploadUrl = new URL(`/upload`, request.url);
    uploadUrl.searchParams.set('uploadNameType', 'origin'); // WebDAV 规范：使用原始文件名
    uploadUrl.searchParams.set('overwrite', 'true'); // WebDAV 规范：允许覆盖已存在的文件
    if (uploadFolder) {
        uploadUrl.searchParams.set('uploadFolder', uploadFolder);
    }

    const othersConfig = await fetchOthersConfig(env);
    const webdavConfig = othersConfig.webDAV || {};
    if (webdavConfig.uploadChannel) {
        uploadUrl.searchParams.set('uploadChannel', webdavConfig.uploadChannel);
    }
    if (webdavConfig.channelName) {
        uploadUrl.searchParams.set('channelName', webdavConfig.channelName);
    }

    try {
        const response = await fetch(uploadUrl.toString(), {
            method: 'POST',
            body: formData,
            headers: await getApiHeaders(env)
        });
        const result = await response.json();
        if (response.ok && Array.isArray(result) && result.length > 0 && result[0].src) {
            return new Response(null, { status: 201 }); // Created
        } else {
            const errorMsg = result.error || JSON.stringify(result);
            console.error('Upload API error:', errorMsg);
            return new Response(`Upload failed: ${errorMsg}`, { status: 500 });
        }
    } catch (error) {
        console.error('Fetch to upload API failed:', error.stack);
        return new Response('Failed to contact upload service', { status: 502 });
    }
}

async function handleDelete(request, env) {
    const path = decodeURIComponent(new URL(request.url).pathname.substring(1));
    if (!path) return new Response('Invalid path for DELETE', { status: 400 });

    let isFolder = path.endsWith('/');
    const cleanPath = isFolder ? path.slice(0, -1) : path;

    if (!isFolder) {
        try {
            const resource = await resourceExists(env, request, cleanPath);
            isFolder = resource.isFolder && !resource.isFile;
        } catch (e) {
            console.error('Folder check in DELETE failed:', e);
        }
    }

    const deleteUrl = new URL(`/api/manage/delete/${encodeURIComponent(cleanPath)}`, request.url);
    if (isFolder) deleteUrl.searchParams.set('folder', 'true');

    try {
        const response = await fetch(deleteUrl.toString(), {
            method: 'DELETE',
            headers: await getApiHeaders(env)
        });
        const result = await response.json();
        if (result.success) {
            return new Response(null, { status: 204 }); // No Content
        } else {
            console.error('Delete API error:', JSON.stringify(result));
            return new Response(`Deletion failed: ${result.error || 'API error'}`, { status: 500 });
        }
    } catch (error) {
        console.error('Delete operation failed:', error.stack);
        return new Response(`Internal server error: ${error.message}`, { status: 500 });
    }
}

async function handlePropfind(request, env) {
    const path = decodeURIComponent(new URL(request.url).pathname);
    const depth = request.headers.get('Depth') || '1';

    try {
        const db = getDatabase(env);

        let isFile = false;
        let fileInfo = null;
        if (path !== '/' && !path.endsWith('/')) {
            const cleanPath = path.startsWith('/') ? path.substring(1) : path;
            const fileData = await db.getWithMetadata(cleanPath);
            if (fileData && fileData.metadata && fileData.metadata.FileType !== 'directory') {
                isFile = true;
                fileInfo = {
                    name: cleanPath,
                    metadata: fileData.metadata
                };
            }
        }

        let isDir = false;
        if (path === '/') {
            isDir = true;
        } else {
            const dir = path.startsWith('/') ? path.substring(1) : path;
            const cleanDir = dir.endsWith('/') ? dir : dir + '/';
            if (await collectionExists(env, request, cleanDir)) {
                isDir = true;
            }
        }

        if (!isFile && !isDir) {
            return new Response('Not Found', { status: 404 });
        }

        let xml;
        if (isFile) {
            xml = `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${createFileXml(fileInfo)}</D:multistatus>`;
        } else {
            const dir = path === '/' ? '' : path.substring(1, path.endsWith('/') ? path.length - 1 : path.length);
            let contents = { files: [], directories: [] };
            if (depth !== '0') {
                contents = await fetchDirectoryContents(dir, env, request);
            }
            xml = generateWebDAVXml(path, contents, depth);
        }

        return new Response(xml, { status: 207, headers: { 'Content-Type': 'application/xml; charset=utf-8' } });
    } catch (error) {
        console.error('Propfind failed:', error.stack);
        return new Response(`Failed to list files: ${error.message}`, { status: 500 });
    }
}

async function handleMove(request, env, context) {
    const destinationHeader = request.headers.get('Destination');
    if (!destinationHeader) {
        return new Response('Destination header is required', { status: 400 });
    }

    let destinationUrl;
    try {
        destinationUrl = new URL(destinationHeader);
    } catch (e) {
        return new Response('Invalid Destination URL', { status: 400 });
    }

    const requestUrl = new URL(request.url);
    if (destinationUrl.host !== requestUrl.host) {
        return new Response('Cannot move resource to a different server', { status: 502 });
    }

    const sourcePath = decodeURIComponent(requestUrl.pathname);
    const cleanSource = sourcePath.startsWith('/') ? sourcePath.substring(1) : sourcePath;

    let destPath = decodeURIComponent(destinationUrl.pathname);
    destPath = destPath.replace(/^\/dav/, '') || '/';
    const cleanDest = destPath.startsWith('/') ? destPath.substring(1) : destPath;

    if (!cleanSource || !cleanDest) {
        return new Response('Invalid source or destination path', { status: 400 });
    }

    const overwrite = request.headers.get('Overwrite') !== 'F';

    try {
        const db = getDatabase(env);

        let isFolder = cleanSource.endsWith('/');
        let lookupSource = isFolder ? cleanSource.slice(0, -1) : cleanSource;
        let lookupDest = cleanDest.endsWith('/') ? cleanDest.slice(0, -1) : cleanDest;

        const sourceResource = await resourceExists(env, request, lookupSource);
        if (!sourceResource.exists) {
            return new Response('Source Not Found', { status: 404 });
        }
        if (isFolder && !sourceResource.isFolder) {
            return new Response('Source Not Found', { status: 404 });
        }
        if (!isFolder && !sourceResource.isFile && sourceResource.isFolder) {
            isFolder = true;
        }

        if (lookupSource === lookupDest) {
            return new Response('Forbidden: Source and destination are the same', { status: 403 });
        }

        if (isFolder && lookupDest.startsWith(lookupSource + '/')) {
            return new Response('Conflict: Cannot move a folder into its own subfolder', { status: 409 });
        }

        if (isFolder && lookupSource.startsWith(lookupDest + '/')) {
            return new Response('Conflict: Cannot overwrite a parent folder with its child', { status: 409 });
        }

        let filesToMove = [];
        let folderKey = null;
        if (isFolder) {
            const listUrl = new URL(`/api/manage/list`, request.url);
            listUrl.searchParams.set('dir', lookupSource);
            listUrl.searchParams.set('count', -1);
            listUrl.searchParams.set('recursive', 'true');

            const listResponse = await fetch(listUrl.toString(), { headers: await getApiHeaders(env) });
            if (!listResponse.ok) {
                return new Response('Failed to list source folder contents', { status: 500 });
            }
            const listData = await listResponse.json();

            folderKey = lookupSource + '/';
            filesToMove = (listData.files || []).filter(file => file.name !== folderKey);
            const unsupportedFile = filesToMove.find(file => isUnsupportedMoveMetadata(file.metadata));
            if (unsupportedFile) {
                return new Response(`Unsupported source file channel: ${unsupportedFile.name}`, { status: 400 });
            }
        } else if (isUnsupportedMoveMetadata(sourceResource.fileData?.metadata)) {
            return new Response('Unsupported source file channel', { status: 400 });
        }

        const destResource = await resourceExists(env, request, lookupDest);
        const destExisted = destResource.exists;
        if (destExisted) {
            if (!overwrite) {
                return new Response('Precondition Failed', { status: 412 });
            }
            if (isFolder && destResource.isFile) {
                return new Response('Conflict: Cannot overwrite a file with a folder', { status: 409 });
            }
            if (!isFolder && destResource.isFolder) {
                return new Response('Conflict: Cannot overwrite a folder with a file', { status: 409 });
            }

            const deleteResult = await deleteResource(env, request, lookupDest, isFolder);
            if (!deleteResult.success) {
                return new Response(`Failed to delete existing destination: ${deleteResult.message}`, { status: 500 });
            }
        }

        if (isFolder) {
            const folderEntry = await db.getWithMetadata(folderKey);
            if (folderEntry && folderEntry.value !== null) {
                const renameUrl = new URL(`/api/manage/rename/${encodeURIComponent(folderKey)}`, request.url);
                const renameResponse = await fetch(renameUrl.toString(), {
                    method: 'POST',
                    headers: {
                        ...(await getApiHeaders(env)),
                        'X-WebDAV-Internal': '1',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ newFileId: lookupDest + '/', overwrite: true })
                });
                if (!renameResponse.ok) {
                    const errorMsg = await renameResponse.text();
                    return new Response(`Failed to move folder entry: ${errorMsg}`, { status: 500 });
                }
            }

            for (const file of filesToMove) {
                const relativePath = file.name.substring(lookupSource.length);
                const newFileId = lookupDest + relativePath;

                const renameUrl = new URL(`/api/manage/rename/${encodeURIComponent(file.name)}`, request.url);
                const renameResponse = await fetch(renameUrl.toString(), {
                    method: 'POST',
                    headers: {
                        ...(await getApiHeaders(env)),
                        'X-WebDAV-Internal': '1',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ newFileId, overwrite: true })
                });

                if (!renameResponse.ok) {
                    const errorMsg = await renameResponse.text();
                    return new Response(`Failed to move file ${file.name}: ${errorMsg}`, { status: 500 });
                }
            }

            return new Response(null, { status: destExisted ? 204 : 201 });
        } else {
            // 单个文件重命名/移动
            const renameUrl = new URL(`/api/manage/rename/${encodeURIComponent(lookupSource)}`, request.url);
            const renameResponse = await fetch(renameUrl.toString(), {
                method: 'POST',
                headers: {
                    ...(await getApiHeaders(env)),
                    'X-WebDAV-Internal': '1',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ newFileId: lookupDest, overwrite: true })
            });

            if (renameResponse.ok) {
                return new Response(null, { status: destExisted ? 204 : 201 });
            } else {
                const errorMsg = await renameResponse.text();
                return new Response(`Rename failed: ${errorMsg}`, { status: 500 });
            }
        }
    } catch (error) {
        console.error('MOVE operation failed:', error.stack);
        return new Response(`Internal server error: ${error.message}`, { status: 500 });
    }
}

async function handleMkcol(request, env) {
    const url = new URL(request.url);
    let folderPath = decodeURIComponent(url.pathname.substring(1))
        .replace(/\.\./g, '_')
        .replace(/\\/g, '/')
        .replace(/\/{2,}/g, '/')
        .replace(/^\/+/, '');
    if (!folderPath || folderPath === '/') {
        return new Response('Invalid path', { status: 400 });
    }
    if (!folderPath.endsWith('/')) {
        folderPath += '/';
    }

    try {
        const db = getDatabase(env);

        const filePath = folderPath.slice(0, -1);
        const existingFile = await db.getWithMetadata(filePath);
        if (existingFile && existingFile.value !== null && existingFile.metadata?.FileType !== 'directory') {
            return new Response('File already exists with the same name', { status: 405 });
        }

        const existing = await db.getWithMetadata(folderPath);
        if (existing && existing.value !== null) {
            // Some WebDAV clients use MKCOL as an "ensure directory" operation during refresh/save.
            return new Response(null, { status: 204 });
        }

        const now = Date.now();
        const metadata = {
            FileName: '',
            FileType: 'directory',
            FileSize: '0',
            FileSizeBytes: 0,
            UploadIP: request.headers.get("cf-connecting-ip") || "",
            UploadAddress: '',
            ListType: 'None',
            TimeStamp: now,
            Label: 'None',
            Directory: folderPath.split('/').slice(0, -2).join('/') === '' ? '' : folderPath.split('/').slice(0, -2).join('/') + '/',
            Tags: []
        };

        await db.put(folderPath, '', { metadata });

        const context = { request, env, url };
        await addFileToIndex(context, folderPath, metadata);

        return new Response(null, { status: 201 });
    } catch (error) {
        console.error('MKCOL failed:', error.stack);
        return new Response(`Internal server error: ${error.message}`, { status: 500 });
    }
}

// --- API DATA FETCHING ---

async function fetchDirectoryContents(dir, env, request) {
    let allFiles = [];
    let allDirectories = [];
    const count = -1; // Fetch all items

    const listUrl = new URL(`/api/manage/list`, request.url);
    listUrl.searchParams.set('dir', dir);
    listUrl.searchParams.set('count', count);

    const response = await fetch(listUrl.toString(), { headers: await getApiHeaders(env) });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API fetch error: Status ${response.status} - ${errorText}`);
    }

    const result = await response.json();
    if (result.error) {
        throw new Error(`API error: ${result.error} - ${result.message}`);
    }

    if (result.files && result.files.length > 0) {
        allFiles = allFiles.concat(result.files.filter(f => !f.name.endsWith('/')));
    }
    if (result.directories && result.directories.length > 0) allDirectories = allDirectories.concat(result.directories);


    return { files: allFiles, directories: [...new Set(allDirectories)] };
}

// --- HTML and XML GENERATION ---

function generateDirectoryListingHtml(basePath, contents) {
    let fileLinks = '';
    let dirLinks = '';

    for (const dir of contents.directories) {
        const fullDirPath = encodePath(`/dav/${dir}/`);
        const dirName = dir.split('/').pop();
        dirLinks += `<li><a href="${fullDirPath}"><strong>${escapeHtml(dirName)}/</strong></a></li>`;
    }

    for (const file of contents.files) {
        const fullFilePath = encodePath(`/dav/${file.name}`);
        const fileName = file.name.split('/').pop();
        const fileSize = file.metadata && file.metadata['FileSize']
            ? `${file.metadata['FileSize']} MB`
            : 'N/A';
        fileLinks += `<li><a href="${fullFilePath}">${escapeHtml(fileName)}</a> - ${escapeHtml(fileSize)}</li>`;
    }

    let parentDirLink = '';
    if (basePath !== '/') {
        const parentPath = new URL('..', `http://dummy.com${basePath}`).pathname;
        parentDirLink = `<li><a href="${encodePath(`/dav${parentPath}`)}"><strong>../ (Parent Directory)</strong></a></li>`;
    }

    const safeBasePath = escapeHtml(basePath);
    return `<!DOCTYPE html><html><head><title>Index of ${safeBasePath}</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>body{font-family:sans-serif;padding:20px}li{margin:5px 0}</style></head><body><h1>Index of ${safeBasePath}</h1><ul>${parentDirLink}${dirLinks}${fileLinks}</ul></body></html>`;
}

function generateWebDAVXml(basePath, contents, depth) {
    let responses = '';
    const prefixPath = basePath.startsWith('/dav/') ? basePath : `/dav${basePath.startsWith('/') ? '' : '/'}${basePath}`;
    const currentPath = prefixPath.endsWith('/') ? prefixPath : `${prefixPath}/`;

    responses += createCollectionXml(currentPath);

    if (depth !== '0') {
        for (const dir of contents.directories) {
            const dirPath = dir.startsWith('dav/') ? `/${dir}/` : `/dav/${dir}/`;
            responses += createCollectionXml(dirPath);
        }
        for (const file of contents.files) {
            responses += createFileXml(file);
        }
    }
    return `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${responses}</D:multistatus>`;
}

function createCollectionXml(path) {
    const now = new Date();
    const creationDate = now.toISOString();
    const lastModified = now.toUTCString();
    const pathWithSlash = path.endsWith('/') ? path : `${path}/`;
    const cleanPath = path.endsWith('/') ? path.slice(0, -1) : path;
    const name = cleanPath.split('/').pop() || '';
    return `<D:response><D:href>${encodePath(pathWithSlash)}</D:href><D:propstat><D:prop><D:displayname>${escapeXml(name)}</D:displayname><D:resourcetype><D:collection/></D:resourcetype><D:creationdate>${creationDate}</D:creationdate><D:getlastmodified>${lastModified}</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`;
}

function createFileXml(file) {
    let fileSize = "0";
    if (file.metadata) {
        if (file.metadata['FileSizeBytes']) {
            fileSize = String(file.metadata['FileSizeBytes']);
        } else if (file.metadata['FileSize']) {
            fileSize = String(Math.round(parseFloat(file.metadata['FileSize']) * 1024 * 1024));
        }
    }
    const fileTime = file.metadata && file.metadata['TimeStamp']
        ? new Date(Number(file.metadata['TimeStamp']))
        : new Date();
    const creationDate = fileTime.toISOString();
    const lastModified = fileTime.toUTCString();
    const contentType = file.metadata && file.metadata['FileType'] ? file.metadata['FileType'] : "application/octet-stream";
    return `<D:response><D:href>${encodePath(`/dav/${file.name}`)}</D:href><D:propstat><D:prop><D:displayname>${escapeXml(file.name.split('/').pop())}</D:displayname><D:resourcetype/><D:creationdate>${creationDate}</D:creationdate><D:getlastmodified>${lastModified}</D:getlastmodified><D:getcontentlength>${fileSize}</D:getcontentlength><D:getcontenttype>${escapeXml(contentType)}</D:getcontenttype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`;
}

function encodePath(path) {
    return path.split('/').map(encodeURIComponent).join('/');
}

function escapeXml(unsafe) {
    return String(unsafe ?? '').replace(/[<>&'"]/g, function (c) {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[<>&'"]/g, function (c) {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&#39;';
            case '"': return '&quot;';
        }
    });
}
