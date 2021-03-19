package com.praphull.experiments.fido.client;

import java.io.IOException;

import okhttp3.Interceptor;
import okhttp3.Response;

public class HeaderInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        return chain.proceed(
                chain.request().newBuilder()
                        .header("X-Requested-With", "XMLHttpRequest")
                        .build());
    }
}
