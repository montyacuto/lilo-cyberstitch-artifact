package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest00078 extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String data = request.getParameter("cmd");
    Runtime.getRuntime().exec(data);
  }
}
