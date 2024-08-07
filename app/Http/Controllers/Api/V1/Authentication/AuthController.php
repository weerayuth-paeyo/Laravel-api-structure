<?php

namespace App\Http\Controllers\Api\V1\Authentication;

use App\Http\Controllers\Controller;
use App\Models\User;
use Defuse\Crypto\Crypto;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use App\Models\OauthAccessToken;
use App\Models\OauthRefreshToken;

class AuthController extends Controller
{

    public function register(Request $request)
    {
        $method = "PUT";
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        $rules = [
            'UserName' => 'required',
            'Email' => 'required|email|unique:users',
            'Password' => 'required',
            'ConfirmPassword' => 'required|same:Password',
        ];

        $validate = Validator::make($request->all(), $rules);
        if ($validate->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => array($validate->errors()),
                "data" => [
                    "error" => "For register and generate Token."
                ],
            ], 400);
        }

        $user_name = $request->UserName;
        $user_email = $request->Email;
        $password = $request->Password;

        $data_create = [
            "name" => $user_name,
            "email" => $user_email,
            "password" => bcrypt($password),
        ];
        $user = User::create($data_create);
        $token = $user->createToken('API Token', ['read', 'write'])->accessToken;

        return response()->json([
            "message" => "success",
            "description" => "For register and generate Token.",
            "data" => array(
                "user" => $user,
                "token" => $token,
            ),
        ], 200);
    }

    public function grantToken(Request $request)
    {
        $method = "POST";
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        $rules = [
            'Email' => 'required|email',
            'Password' => 'required',
        ];

        $validate = Validator::make($request->all(), $rules);
        if ($validate->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => array($validate->errors()),
                "data" => [
                    "error" => "Fields required and data type."
                ],
            ], 400);
        }


        $user_email = $request->Email;
        $password = $request->Password;
        $param = [
            "email" => $user_email,
            "password" => $password,
        ];
        $auth = Auth::attempt($param);
        if (!$auth) {
            return response()->json([
                "message" => "failed",
                "description" => "Email or Password incorrect. Please try again.",
                "data" => [
                    "error" => "Unauthorized"
                ],
            ], 401);
        }

        if (Auth::user()->status != "2") {
            return response()->json([
                "message" => "failed",
                "description" => "Unapproved users verify user status",
                "data" => [
                    "error" => "Unapproved users verify user status"
                ],
            ], 403);
        }

        Auth::user()->tokens->each(function ($token, $key) {
            if ($token) {
                OauthRefreshToken::where('access_token_id', $token->id)->delete();
                $token->delete();
            }
        });

        $response = Http::asForm()->post(url('/oauth/token'), [
            'grant_type' => 'password',
            'client_id' => env('CLIENT_ID'),
            'client_secret' => env('CLIENT_SECRET'),
            'username' => $param['email'],
            'password' => $param['password'],
            'scope' => "read write",
        ]);

        return response()->json([
            "message" => "success",
            "description" => "",
            "data" => $response->json(),
        ], 200);
    }

    public function approveAccessUser(Request $request, $user_id = null)
    {
        $method = "POST";
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        if ($user_id == null) {
            return response()->json([
                "message" => "failed",
                "description" => "User ID required.",
                "data" => [
                    "error" => ""
                ],
            ], 404);
        }

        $rules = [
            'Status' => 'required|string|in:delete,inactive,active',
        ];

        $validate = Validator::make($request->all(), $rules);
        if ($validate->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => array($validate->errors()),
                "data" => [
                    "error" => "For register and generate Token."
                ],
            ], 400);
        }

        try {
            $status = $request->Status;
            $status_value = [
                'delete' => '0',
                'inactive' => '1',
                'active' => '2'
            ];

            $user = User::find($user_id);
            if (!$user) {
                return response()->json([
                    "message" => "failed",
                    "description" => "User ID : $user_id Notfound.",
                    "data" => [],
                ], 404);
            }

            $user->status = $status_value[$status];
            if ($user->update()) {
                Auth::loginUsingId($user_id);
                return response()->json([
                    "message" => "success",
                    "description" => "User status updated successfully",
                    "data" => array(
                        "user" => Auth::user(),
                    ),
                ], 200);
            }
        } catch (\Exception $e) {
            return response()->json([
                "message" => "failed",
                "description" => "For approve access user",
                "data" => [
                    "error" => $e->getMessage()
                ],
            ], 400);
        }
    }

    public function approveScopeToken(Request $request, $user_id = null)
    {
        $method = "POST";
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        if ($user_id == null) {
            return response()->json([
                "message" => "failed",
                "description" => "User ID required.",
                "data" => [
                    "error" => ""
                ],
            ], 404);
        }

        $rules = [
            'Scope' => 'required|array|in:read,write',
        ];

        $validate = Validator::make($request->all(), $rules);
        if ($validate->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => array($validate->errors()),
                "data" => [
                    "error" => "For register and generate Token."
                ],
            ], 400);
        }

        $scope = $request->Scope;
        try {
            $user = User::find($user_id);
            if (!$user) {
                return response()->json([
                    "message" => "failed",
                    "description" => "User ID : $user_id Notfound.",
                    "data" => [],
                ], 404);
            }

            $auth = Auth::loginUsingId($user_id);
            if (!$auth) {
                return response()->json([
                    "message" => "failed",
                    "description" => "Email or Password incorrect. Please try again.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }

            $oauth_access_tokens = OauthAccessToken::where([
                ['user_id', '=', $user_id],
                ['revoked', '=', '0']
            ])->orderBy('created_at', 'desc');

            $model = $oauth_access_tokens;
            if (!count($model->get())) {
                return response()->json([
                    "message" => "failed",
                    "description" => "Token of User ID : " . $user_id . " not found.",
                    "data" => [],
                ], 400);
            }

            if ($oauth_access_tokens->update(['scopes' => $scope])) {
                return response()->json([
                    "message" => "success",
                    "description" => "For approve scope token.",
                    "data" => Auth::user(),
                ], 200);
            }
        } catch (\Exception $e) {
            return response()->json([
                "message" => "failed",
                "description" => "For approve scope token",
                "data" => array(
                    "error" => $e->getMessage()
                ),
            ], 400);
        }
    }

    public function refreshingToken(Request $request)
    {
        $method = "POST";
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        $rules = [
            'Email' => 'required|email',
            'Password' => 'required|string',
            'RefreshToken' => 'required|string',
            'Scope' => 'nullable|array|in:read,write',
        ];

        $validate = Validator::make($request->all(), $rules);
        if ($validate->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => array($validate->errors()),
                "data" => [
                    "error" => "For register and generate Token."
                ],
            ], 400);
        }

        $email = $request->Email;
        $password = $request->Password;
        $refresh_token = $request->RefreshToken;
        $scope = $request->Scope ?? ['read'];

        try {
            if (!Auth::attempt(["email" => $email, "password" => $password])) {
                return response()->json([
                    "message" => "failed",
                    "description" => "Email or Password incorrect. Please try again.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }

            $refresh_token_details = $this->decodeRefreshToken($refresh_token);
            if (!is_array($refresh_token_details) || !array_key_exists('user_id', $refresh_token_details)) {
                return response()->json([
                    "message" => "failed",
                    "description" => "refresh token incorrect. Please try again.",
                    "data" => [],
                ], 400);
            }

            if ($refresh_token_details['user_id'] != Auth::user()->id) {
                return response()->json([
                    "message" => "failed",
                    "description" => "email and password not match refresh token.",
                    "data" => [],
                ], 400);
            }

            $response = Http::asForm()->post(url('/oauth/token'), [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refresh_token,
                'client_id' => env('CLIENT_ID'),
                'client_secret' => env('CLIENT_SECRET'),
                'scope' => $scope,
            ]);

            Auth::user()->tokens->each(function ($token, $key) {
                if ($token && $token->revoked == '1') {
                    OauthRefreshToken::where('access_token_id', $token->id)->delete();
                    $token->delete();
                }
            });

            if (is_array(json_decode($response, true)) && array_key_exists('error', json_decode($response, true))) {
                return response()->json([
                    "message" => "failed",
                    "description" => "For refresh token",
                    "data" => $response->json()
                ], 400);
            }

            return $response->json();
        } catch (\Exception $e) {
            return response()->json([
                "message" => "failed",
                "description" => "For refresh token",
                "data" => array(
                    "error" => $e->getMessage()
                ),
            ], 400);
        }
    }

    public function revokeToken(Request $request, $user_id = null)
    {
        $method = "POST";
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        if ($user_id == null) {
            return response()->json([
                "message" => "failed",
                "description" => "User ID required.",
                "data" => [
                    "error" => ""
                ],
            ], 404);
        }

        $rules = [
            'Status' => 'required|string|in:delete,revoke',
        ];

        $validate = Validator::make($request->all(), $rules);
        if ($validate->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => array($validate->errors()),
                "data" => [
                    "error" => "For register and generate Token."
                ],
            ], 400);
        }

        $status = $request->Status;
        try {
            $auth = Auth::loginUsingId($user_id);
            if (!$auth) {
                return response()->json([
                    "message" => "failed",
                    "description" => "Email or Password incorrect. Please try again.",
                    "data" => [
                        "error" => "Unauthorized"
                    ],
                ], 401);
            }

            Auth::user()->tokens->each(function ($token, $key) use ($status) {
                if ($token) {
                    if ($status == 'delete') {
                        OauthRefreshToken::where('access_token_id', $token->id)->delete();
                        $token->delete();
                    } else {
                        OauthRefreshToken::where('access_token_id', $token->id)->update(['revoked' => '1']);
                        $token->revoke();
                    }
                }
            });

            return response()->json([
                "message" => "success",
                "description" => "revoke token",
                "data" => array(
                    "user" => Auth::user(),
                ),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                "message" => "failed",
                "description" => "For revoke token",
                "data" => array(
                    "error" => $e->getMessage()
                ),
            ], 400);
        }
    }

    public function decodeJwt(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                "message" => "failed",
                "description" => "For logged in and generate Token.",
                "data" => array(
                    "error" => $validator->errors()
                ),
            ], 400);
        }
        return json_decode(base64_decode(str_replace('_', '/', str_replace('-', '+', explode('.', $request->token)[1]))));
    }

    private function decodeRefreshToken($refresh_token)
    {
        $app_key = env('APP_KEY');
        $enc_key = base64_decode(substr($app_key, 7));
        try {
            $crypto = Crypto::decryptWithPassword($refresh_token, $enc_key);
        } catch (\Exception $e) {
            return response()->json([
                "message" => "failed",
                "description" => "For decode",
                "data" => array(
                    "error" => $e->getMessage()
                ),
            ], 400);
        }
        return json_decode($crypto, true);
    }

}
