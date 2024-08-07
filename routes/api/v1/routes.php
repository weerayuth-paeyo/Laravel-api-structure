<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

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
$cont_method = ['get', 'post', 'put', 'patch', 'delete'];

Route::match($cont_method, '/v1', function (Request $request) {
    return "Welcome to API Version 1.0";
});

Route::middleware(['log.request.in'])->prefix('/v1')->group(function () use ($cont_method) {

    Route::match($cont_method, '/register', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'register']);
    Route::match($cont_method, '/approve-user/{user_id?}', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'approveAccessUser']);
    Route::match($cont_method, '/grant-token', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'grantToken']);
    Route::match($cont_method, '/approve-scope/{user_id?}', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'approveScopeToken']);
    Route::match($cont_method, '/refreshing-token', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'refreshingToken']);
    Route::match($cont_method, '/revoke-token/{user_id?}', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'revokeToken']);
    Route::match($cont_method, '/decode-jwt', [App\Http\Controllers\Api\V1\Authentication\AuthController::class,'decodeJwt']);

    Route::middleware(['auth.smart'])->group(function () use ($cont_method) {
        testAuth($cont_method);

        Route::match($cont_method, '/example_path_rul', [\App\Http\Controllers\Api\V2\StructureController::class, 'index']);

    });
});
