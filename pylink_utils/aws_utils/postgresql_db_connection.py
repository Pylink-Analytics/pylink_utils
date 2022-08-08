from typing import Optional, Dict, List

import awswrangler as wr
import boto3
import pandas as pd


class PostgreSQLDatabaseConnection:
    """Handler to connect to db using aws wrangler

    In order for this to work, you must first set up aws config correctly in the root directory of the user.

    1) Make sure you have the aws CLI installed on your machine,
        - check if it is already installed by running "aws --version" in the cmd line
        - if you haven't got it installed then follow the process outlined at
        https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

    2) Set-up your config and credential files as described at
    https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html

    3) Correctly set-up config and credential files will resemble the following

        config:
        [default]
        region = eu-west-1
        output = json

        [profile intriva]
        region = eu-west-2
        output = json

        credentials:
        [default]
        aws_access_key_id = ******************
        aws_secret_access_key = *********************************
        [intriva]
        aws_access_key_id = ********************
        aws_secret_access_key = **************************************

    """

    def __init__(self, glue_connection: str,  profile_name: str = None):
        session = boto3.session.Session(profile_name=profile_name)
        self._connection = wr.postgresql.connect(connection=glue_connection, boto3_session=session)

    def upload_df_to_db(
        self,
        df: pd.DataFrame,
        table: str,
        schema: str = "public",
        mode: str = "append",
        index: bool = False,
        dtype: Optional[Dict[str, str]] = None,
        varchar_lengths: Optional[Dict[str, int]] = None,
        use_column_names: bool = True,
        chunksize: int = 200,
        upsert_conflict_columns: Optional[List[str]] = None,
        insert_conflict_columns: Optional[List[str]] = None,
    ):
        wr.postgresql.to_sql(
            df=df,
            con=self._connection,
            table=table,
            schema=schema,
            mode=mode,
            index=index,
            dtype=dtype,
            varchar_lengths=varchar_lengths,
            use_column_names=use_column_names,
            chunksize=chunksize,
            upsert_conflict_columns=upsert_conflict_columns,
            insert_conflict_columns=insert_conflict_columns,
        )

    def unload_query(self, query: str) -> pd.DataFrame:
        return wr.postgresql.read_sql_query(query, con=self._connection)
