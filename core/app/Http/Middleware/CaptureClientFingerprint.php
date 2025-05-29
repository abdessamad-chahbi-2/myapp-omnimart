<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;

class CaptureClientFingerprint
{
    public function handle(Request $request, Closure $next)
    {
        // $fingerprint = $request->cookie('client_fingerprint', 'NO_FP');
        // $publicIp = $request->cookie('client_public_ip', 'NO_IP');
        $fingerprint = $request->cookie('client_fingerprint') ?? '-';
        $publicIp = $request->cookie('client_public_ip') ?? '-';
        // $publicIp = $request->ip() ?? '-'; // <-- récupère l'IP réelle à chaque requête

        // $start = microtime(true);
        $response = $next($request); // On continue la requête
        // $requestDuration = (int)((microtime(true) - $start) * 1000); // en ms

        // Récupération des données
        $remoteLogname = '-';
        $remoteUser = '-';
        $timestamp = now()->format('d/M/Y:H:i:s O');
        // $requestLine = $request->method() + $request->getRequestUri() + $request->server('SERVER_PROTOCOL');
        $requestLine = $request->method() . ' ' . $request->fullUrl() . ' ' . $request->server('SERVER_PROTOCOL');
        $statusCode = $response->getStatusCode();
        $responseSize = strlen($response->getContent());
        $httpReferer = $request->header('Referer', '-');
        $userAgent = $request->userAgent();
        $requestDuration = rand(1, 999); // En ms
        $sessionID = Session::getId() ?: '-';
        // $threadID = '-'; // Laravel n’a pas de thread ID, remplace par '-' ==> $threadID = Str::uuid();   // Simule un thread ID
        $acceptHeader = $request->header('Accept', '-');
        $acceptLanguage = $request->header('Accept-Language', '-');
        $authorization = $request->header('Authorization', '-');
        $xForwardedFor = $request->header('X-Forwarded-For', '-');

        // Format style AccessLogValve
        $log = sprintf(
            '%s %s %s %s [%s] "%s" %d %d "%s" "%s" %d %s "%s" "%s" "%s" "%s"',
            $fingerprint,
            $publicIp,
            $remoteLogname,
            $remoteUser,
            $timestamp,
            $requestLine,
            $statusCode,
            $responseSize,
            $httpReferer,
            $userAgent,
            $requestDuration,
            $sessionID,
            // $threadID,
            $acceptHeader,
            $acceptLanguage,
            $authorization,
            $xForwardedFor
        );

        // Log::channel('client_audit')->info($log);

        // Génère un nom de fichier basé sur la date du jour
        $logFilename = 'web-access-' . now()->format('Y-m-d') . '.log';
        // Écriture directe dans un fichier log sans préfixe avec la date du jour
        file_put_contents(
            storage_path("logs/{$logFilename}"),
            $log . PHP_EOL,
            FILE_APPEND | LOCK_EX
        ); 

        return $next($request); // return $response;
    }
}
