<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Token;

class SmartAuthentication
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
        Log::channel('authentications')->info("================================================");
        Log::channel('authentications')->info("Token | " . $request->header('authorization'));
        Log::channel('authentications')->info("Path | " . \Illuminate\Support\Facades\Request::url());
        Log::channel('authentications')->info("================================================");

        $token = $request->header('Authorization');
        if (!$token) {
            return response()->json([
                "message" => "failed",
                "description" => "Please check your Token is not empty.",
                "data" => [
                    "error" => "Unauthorized"
                ],
            ], 401);
        }

        if ($request->header('Php-Auth-User') && $request->header('Php-Auth-Pw')) {
            $auth = Auth::attempt(["email" => $request->header('Php-Auth-User'), "password" => $request->header('Php-Auth-Pw')]);
            if (!$auth) {
                return response()->json([
                    "message" => "failed",
                    "description" => "Email or Password incorrect. Please try again.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }
            if (auth()->user()->status == 0){
                return response()->json([
                    "message" => "failed",
                    "description" => "This account is temporarily suspended.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }
        } else {
            if (!auth('api')->user()){
                return response()->json([
                    "message" => "failed",
                    "description" => "This access token incorrect. Please try again.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }


            if (auth('api')->user()->status == 0){
                return response()->json([
                    "message" => "failed",
                    "description" => "This account is temporarily suspended.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }

            if (auth('api')->check()) {
                return $next($request);
            }

            return response()->json([
                "message" => "failed",
                "description" => "Please check your Token may be not expire.",
                "data" => [
                    "error" => "Unauthorized"
                ],
            ], 401);
        }
        return $next($request);
    }
}
