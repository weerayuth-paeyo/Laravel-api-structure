<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

class Auth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if ($request->header('Php-Auth-User') && $request->header('Php-Auth-Pw')) {
            $auth = \Illuminate\Support\Facades\Auth::attempt(["email" => $request->header('Php-Auth-User'), "password" => $request->header('Php-Auth-Pw')]);
            if (!$auth) {
                return response()->json([
                    "message" => "failed",
                    "description" => "Email or Password incorrect. Please try again.",
                    "data" => [],
                ], 401);
            }
        }
        Session::put('basic_auth', true);
        return $next($request);
    }
}
