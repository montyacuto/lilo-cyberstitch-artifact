package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest00079 extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String ignored = request.getParameter("cmd");
    String command = "echo cyberstitch-safe";
    Runtime.getRuntime().exec(command);
    response.getWriter().println(ignored.length());
  }
}
