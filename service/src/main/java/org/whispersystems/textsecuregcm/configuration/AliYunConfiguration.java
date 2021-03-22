/**
 * Copyright (C) 2018 Open WhisperSystems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.NotEmpty;

public class AliYunConfiguration {
  @NotEmpty
  @JsonProperty
  private String AccessKeyId;

  @NotEmpty
  @JsonProperty
  private String AccessKeySecret;

  @NotEmpty
  @JsonProperty
  private String TemplateCode;

  @NotEmpty
  @JsonProperty
  private String SignName;

  public String getAccessKeyId() {
    return AccessKeyId;
  }

  public void setAccessKeyId(String accessKeyId) {
    AccessKeyId = accessKeyId;
  }

  public String getAccessKeySecret() {
    return AccessKeySecret;
  }

  public void setAccessKeySecret(String accessKeySecret) {
    AccessKeySecret = accessKeySecret;
  }

  public String getTemplateCode() {
    return TemplateCode;
  }

  public void setTemplateCode(String templateCode) {
    TemplateCode = templateCode;
  }

  public String getSignName() {
    return SignName;
  }

  public void setSignName(String signName) {
    SignName = signName;
  }
}

   
