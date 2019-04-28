import pandas as pd
import pprint

pp = pprint.PrettyPrinter(indent=4)

def debug_dataframe(
        df: pd.DataFrame,
        msg,
        # intro="Debugging dataframe", 
        nrows=5,
        usecols=None,
        **kwargs
    ):
    '''
    test
    '''
    # if use_cols is None:
    #     use_cols=[]
    # pd.set_option('display.max_rows', 200)
    # pd.set_option('display.max_colwidth', -1)
    # verbose=True
    intro = """
    === Debug dataframe ===
    {msg}
    """
    print(intro.format(msg=msg))
    print(df.info())
    # print(df.columns)
    # print(df.dtypes)
    print(pp.pformat(df.dtypes))
    with pd.option_context('float_format', '{:f}'.format):
        sdf = df
        if usecols:
            sdf = df[usecols]
        print(sdf.head(nrows, ))

# https://stackoverflow.com/questions/52686559/read-csv-get-the-line-where-exception-occured
def read_csv_debug(fields, fd, *args, first_try=True, **kwargs):
    """
    Help debugging dataframe loading errors (with dtypes/converters)
    chunksize: bool,
    """

    chunksize = kwargs.get("chunksize")

    if first_try:
        kwargs.pop("chunksize", None)

    for field in fields:
        print("TESTING field %s (first_try ? %s ) " % (field, first_try))
        print(kwargs.get("dtype")[field])
        try:
            res = pd.read_csv(
                fd,
                *args,
                usecols=[ field],
                **kwargs
            )
            if chunksize is not None:
                for i, chunk in enumerate(res):
                    # print("chunk %d" % i)
                    print(chunk)
        except TypeError as e:
            # TODO retry with chunksize
            if first_try:
                kwargs.update({"chunksize": chunksize  or 40})
                fd.seek(0)
                read_csv_debug([field], fd, *args, first_try=False, **kwargs)
            else:
                print(fd.readlines(chunksize))
                raise e

        finally:
            fd.seek(0)


