<?php

use App\Lib\SmartAuthentication;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

function testAuth($cont_method)
{
    Route::match($cont_method, '/test_auth', function (Request $request) {
        $method = 'GET';
        if (!$request->isMethod($method)) {
            return response()->json([
                "message" => "failed",
                "description" => "This method is support '$method' Only",
                "data" => [
                    "error" => ""
                ],
            ], 400);
        }

        $scope = 'write';
        if (!SmartAuthentication::checkScope($scope)) {
            return response()->json([
                "message" => "failed",
                "description" => "Your scope can't " . $scope . " data.",
                "data" => [
                    "error" => "Permission access denied."
                ],
            ], 403);
        }

        return response()->json([
            "message" => "success",
            "description" => "for test authentication.",
            "data" => $request,
        ], 200);
    });

}
