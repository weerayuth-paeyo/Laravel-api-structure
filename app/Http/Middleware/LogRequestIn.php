<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class LogRequestIn
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        Log::channel('request_in')->info("================================================");
        Log::channel('request_in')->info("Method | " . $request->method());
        Log::channel('request_in')->info("Path | " . \Illuminate\Support\Facades\Request::url());
        Log::channel('request_in')->info("User-Agent | " . $request->header('User-Agent'));
        Log::channel('request_in')->info("Host | " . $request->header('host'));
        Log::channel('request_in')->info("IP | " . $request->header('x-forwarded-for'));
        Log::channel('request_in')->info("Header All | " . json_encode($request->header()));
        Log::channel('request_in')->info("Body | " . json_encode($request->all()));
        Log::channel('request_in')->info("================================================");
        return $next($request);
    }
}
