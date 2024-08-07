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

Route::match($cont_method, '/v2', function (Request $request) {
    return "Welcome to API Version 2.0";
});

Route::middleware(['log.request.in'])->prefix('/v2')->group(function () use ($cont_method) {
    Route::middleware(['auth.smart'])->group(function () use ($cont_method) {
        testAuth($cont_method);

        Route::match($cont_method, '/example_path_rul', [\App\Http\Controllers\Api\V2\StructureController::class, 'index']);

    });
});
