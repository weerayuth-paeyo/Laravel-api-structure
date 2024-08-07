<?php

namespace App\Lib;

use Illuminate\Support\Facades\DB;

class SmartAuthentication
{
    static function checkScope($scope)
    {
        if (auth()->user()) {
            $scopes = DB::table('oauth_access_tokens')
                ->select('oauth_access_tokens.scopes')
                ->where('oauth_access_tokens.user_id', auth()->user()->id)->first();
            $scopes = json_decode($scopes->scopes);
            if (in_array($scope, $scopes)) {
                $check_scope = true;
            } else {
                $check_scope = false;
            }
        } elseif (auth('api')->user()) {
            $check_scope = auth('api')->user()->tokenCan($scope);
        } else {
            $check_scope = false;
        }
        return $check_scope;
    }
}
